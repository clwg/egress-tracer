package tui

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/clwg/egress-tracer/pkg/cache"
	"github.com/clwg/egress-tracer/pkg/types"
)

type sortColumn int

const (
	sortByProcess sortColumn = iota
	sortByDestination
	sortByPort
	sortByProtocol
	sortByFirstSeen
	sortByLastSeen
	sortByCount
	sortBySHA256
)

type popupType int

const (
	popupDetails popupType = iota
	popupWhitelist
)

type ConnectionData struct {
	Event     *types.Event
	Count     int
	LastSeen  time.Time
	FirstSeen time.Time
}

type Model struct {
	table               table.Model
	connections         map[string]*ConnectionData
	sortBy              sortColumn
	sortDesc            bool
	totalEvents         int
	startTime           time.Time
	selectedRow         int
	width               int
	height              int
	showPopup           bool
	popupType           popupType
	popupData           *ConnectionData
	cacheMaxSize        int
	cacheTTL            time.Duration
	lastCleanup         time.Time
	processCache        *cache.ProcessCache
	whitelistFile       string
	whitelistInput      textinput.Model
	whitelistConfirming bool
}

type EventMsg struct {
	Event *types.Event
}

type tickMsg time.Time

func tickCmd() tea.Cmd {
	return tea.Tick(2*time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func NewModel(cacheMaxSize int, cacheTTL time.Duration) Model {
	return NewModelWithCache(cacheMaxSize, cacheTTL, nil, "")
}

func NewModelWithCache(cacheMaxSize int, cacheTTL time.Duration, processCache *cache.ProcessCache, whitelistFile string) Model {
	// Initialize with default column headers (will be updated dynamically)
	columns := []table.Column{
		{Title: "Process", Width: 19},
		{Title: "Destination", Width: 22},
		{Title: "Port", Width: 12},
		{Title: "Protocol", Width: 15},
		{Title: "First Seen", Width: 18},
		{Title: "Last Seen", Width: 17},
		{Title: "Count", Width: 12},
		{Title: "SHA256", Width: 20},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(15), // Will be updated dynamically based on terminal size
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)
	t.SetStyles(s)

	// Initialize text input for whitelist comments
	ti := textinput.New()
	ti.Placeholder = "Enter description for whitelist entry..."
	ti.CharLimit = 100
	ti.Width = 50

	m := Model{
		table:          t,
		connections:    make(map[string]*ConnectionData),
		sortBy:         sortByLastSeen,
		sortDesc:       true,
		startTime:      time.Now(),
		cacheMaxSize:   cacheMaxSize,
		cacheTTL:       cacheTTL,
		lastCleanup:    time.Now(),
		processCache:   processCache,
		whitelistFile:  whitelistFile,
		whitelistInput: ti,
	}

	// Set initial column headers with sort indicators
	m.updateColumnHeaders()

	return m
}

func (m Model) Init() tea.Cmd {
	return tickCmd() // Start the cleanup timer
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		// Calculate table height: total height - header (3 lines) - instructions (3 lines) - minimal bottom padding
		m.table.SetHeight(msg.Height - 5)
		return m, nil

	case EventMsg:
		m.addEvent(msg.Event)
		m.updateTable()
		return m, nil

	case tickMsg:
		// Periodic cleanup independent of new events
		entriesRemoved := m.evictExpiredEntries(time.Now())
		if entriesRemoved > 0 {
			m.updateTable()
		}
		return m, tickCmd() // Schedule next tick

	case tea.KeyMsg:
		// Handle popup-specific keys first
		if m.showPopup {
			switch msg.String() {
			case "q", "ctrl+c":
				return m, tea.Quit

			case "esc":
				m.showPopup = false
				m.popupType = popupDetails
				m.popupData = nil
				m.whitelistConfirming = false
				m.whitelistInput.SetValue("")
				m.whitelistInput.Blur()
				return m, nil

			case "enter":
				if m.popupType == popupWhitelist && !m.whitelistConfirming {
					// First enter - confirm the whitelist entry
					m.whitelistConfirming = true
					return m, nil
				} else if m.popupType == popupWhitelist && m.whitelistConfirming {
					// Second enter - actually add to whitelist
					if err := m.addToWhitelist(); err != nil {
						// TODO: Show error message - for now just close popup
					}
					m.showPopup = false
					m.popupType = popupDetails
					m.popupData = nil
					m.whitelistConfirming = false
					m.whitelistInput.SetValue("")
					return m, nil
				} else if m.popupType == popupDetails {
					// Close details popup
					m.showPopup = false
					m.popupData = nil
					return m, nil
				}
			}
			// For whitelist popup, handle text input
			if m.popupType == popupWhitelist {
				m.whitelistInput, cmd = m.whitelistInput.Update(msg)
				return m, cmd
			}
			// Other keys are ignored when popup is shown
			return m, nil
		}

		// Handle main window keys only when no popup is shown
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit

		case "enter":
			m.showPopup = true
			m.popupType = popupDetails
			m.popupData = m.getSelectedConnection()
			return m, nil

		case "w":
			if m.whitelistFile != "" {
				// Open whitelist popup for selected connection (only if whitelist is configured)
				selectedData := m.getSelectedConnection()
				if selectedData != nil && selectedData.Event.ProcessSHA256 != "" {
					m.showPopup = true
					m.popupType = popupWhitelist
					m.popupData = selectedData
					m.whitelistInput.Focus()
				}
			}
			return m, nil

		case "1":
			m.sortBy = sortByProcess
			m.sortDesc = !m.sortDesc
			m.updateTable()

		case "2":
			m.sortBy = sortByDestination
			m.sortDesc = !m.sortDesc
			m.updateTable()

		case "3":
			m.sortBy = sortByPort
			m.sortDesc = !m.sortDesc
			m.updateTable()

		case "4":
			m.sortBy = sortByProtocol
			m.sortDesc = !m.sortDesc
			m.updateTable()

		case "5":
			m.sortBy = sortByFirstSeen
			m.sortDesc = !m.sortDesc
			m.updateTable()

		case "6":
			m.sortBy = sortByLastSeen
			m.sortDesc = !m.sortDesc
			m.updateTable()

		case "7":
			m.sortBy = sortByCount
			m.sortDesc = !m.sortDesc
			m.updateTable()

		case "8":
			m.sortBy = sortBySHA256
			m.sortDesc = !m.sortDesc
			m.updateTable()

		case "r":
			// Refresh - clear all data
			m.connections = make(map[string]*ConnectionData)
			m.totalEvents = 0
			m.startTime = time.Now()
			m.updateTable()
		}
	}

	// Update table only when no popup is shown
	if !m.showPopup {
		m.table, cmd = m.table.Update(msg)
	}
	return m, cmd
}

func (m *Model) View() string {
	if m.showPopup && m.popupData != nil {
		if m.popupType == popupWhitelist {
			return m.renderWhitelistPopup()
		}
		return m.renderDetailsPopup()
	}

	var b strings.Builder

	// Header with stats
	headerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("86")).
		Bold(true).
		Padding(0, 1)

	statsStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("243")).
		Padding(0, 1)

	uptime := time.Since(m.startTime).Round(time.Second)
	header := headerStyle.Render("Egress Tracer") +
		statsStyle.Render(fmt.Sprintf("Uptime: %v | Total Events: %d | Current Records: %d",
			uptime, m.totalEvents, len(m.connections)))

	b.WriteString(header + "\n\n")

	// Instructions above table
	helpStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("241")).
		Padding(0, 1)

	var helpText string
	if m.whitelistFile != "" {
		helpText = "Keys: 1-8 sort columns | enter details | w whitelist process | r reset | q quit"
	} else {
		helpText = "Keys: 1-8 sort columns | enter details | r reset | q quit"
	}
	help := helpStyle.Render(helpText)
	b.WriteString(help + "\n\n")

	// Table
	b.WriteString(m.table.View())

	return b.String()
}

func (m *Model) addEvent(event *types.Event) {
	// Group by SHA256, destination, port, and process
	key := fmt.Sprintf("%s:%s:%d:%s", event.ProcessSHA256, event.Destination, event.Port, event.Process)

	now := time.Now()
	if conn, exists := m.connections[key]; exists {
		conn.Count++
		conn.LastSeen = now
		conn.Event = event // Update with latest event data
	} else {
		m.connections[key] = &ConnectionData{
			Event:     event,
			Count:     1,
			LastSeen:  now,
			FirstSeen: now,
		}
	}
	m.totalEvents++

	// Perform cache cleanup if needed
	m.evictCacheIfNeeded()
}

func (m *Model) updateTable() {
	m.updateColumnHeaders()
	rows := m.getSortedRows()
	m.table.SetRows(rows)
}

func (m *Model) updateColumnHeaders() {
	baseColumns := []string{"Process", "Destination", "Port", "Protocol", "First Seen", "Last Seen", "Count", "SHA256"}
	widths := []int{19, 22, 12, 15, 19, 19, 12, 20}

	columns := make([]table.Column, len(baseColumns))
	for i, title := range baseColumns {
		// Add column number in parentheses before the title
		displayTitle := fmt.Sprintf("(%d) %s", i+1, title)
		if sortColumn(i) == m.sortBy {
			arrow := " ↑"
			if m.sortDesc {
				arrow = " ↓"
			}
			displayTitle = displayTitle + arrow
		}
		columns[i] = table.Column{Title: displayTitle, Width: widths[i]}
	}

	m.table.SetColumns(columns)
}

func (m *Model) getSortedRows() []table.Row {
	connections := m.getSortedConnections()

	var rows []table.Row
	for _, conn := range connections {
		sha256Display := truncate(conn.Event.ProcessSHA256, 15)
		if sha256Display == "" {
			sha256Display = "N/A"
		}
		rows = append(rows, table.Row{
			truncate(conn.Event.Process, 14),
			truncate(conn.Event.Destination, 17),
			fmt.Sprintf("%d", conn.Event.Port),
			conn.Event.Protocol,
			conn.FirstSeen.Format("2006-01-02 15:04:05"),
			conn.LastSeen.Format("2006-01-02 15:04:05"),
			fmt.Sprintf("%d", conn.Count),
			sha256Display,
		})
	}

	return rows
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func (m *Model) getSelectedConnection() *ConnectionData {
	cursor := m.table.Cursor()
	connections := m.getSortedConnections()
	if cursor < len(connections) {
		return connections[cursor]
	}
	return nil
}

func (m *Model) getSortedConnections() []*ConnectionData {
	var connections []*ConnectionData
	for _, conn := range m.connections {
		connections = append(connections, conn)
	}

	sort.Slice(connections, func(i, j int) bool {
		switch m.sortBy {
		case sortByLastSeen:
			if m.sortDesc {
				return connections[i].LastSeen.After(connections[j].LastSeen)
			}
			return connections[i].LastSeen.Before(connections[j].LastSeen)
		case sortByProcess:
			if m.sortDesc {
				return connections[i].Event.Process > connections[j].Event.Process
			}
			return connections[i].Event.Process < connections[j].Event.Process
		case sortBySHA256:
			if m.sortDesc {
				return connections[i].Event.ProcessSHA256 > connections[j].Event.ProcessSHA256
			}
			return connections[i].Event.ProcessSHA256 < connections[j].Event.ProcessSHA256
		case sortByProtocol:
			if m.sortDesc {
				return connections[i].Event.Protocol > connections[j].Event.Protocol
			}
			return connections[i].Event.Protocol < connections[j].Event.Protocol
		case sortByDestination:
			if m.sortDesc {
				return connections[i].Event.Destination > connections[j].Event.Destination
			}
			return connections[i].Event.Destination < connections[j].Event.Destination
		case sortByPort:
			if m.sortDesc {
				return connections[i].Event.Port > connections[j].Event.Port
			}
			return connections[i].Event.Port < connections[j].Event.Port
		case sortByCount:
			if m.sortDesc {
				return connections[i].Count > connections[j].Count
			}
			return connections[i].Count < connections[j].Count
		case sortByFirstSeen:
			if m.sortDesc {
				return connections[i].FirstSeen.After(connections[j].FirstSeen)
			}
			return connections[i].FirstSeen.Before(connections[j].FirstSeen)
		}
		return false
	})

	return connections
}

func (m *Model) renderDetailsPopup() string {
	data := m.popupData
	if data == nil {
		return ""
	}

	// Define consistent field styling
	labelStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("86")).
		Bold(true)

	valueStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("255"))

	// Build content with consistent formatting
	var content strings.Builder

	// Title
	titleStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("86")).
		Bold(true).
		Underline(true)

	content.WriteString(titleStyle.Render("Connection Details"))
	content.WriteString("\n\n")

	// Helper function to add a field
	addField := func(label, value string) {
		content.WriteString(labelStyle.Render(fmt.Sprintf("%-16s", label+":")))
		content.WriteString(" ")
		content.WriteString(valueStyle.Render(value))
		content.WriteString("\n")
	}

	// Add all fields
	addField("Process", data.Event.Process)
	addField("PID", fmt.Sprintf("%d", data.Event.PID))
	addField("TGID", fmt.Sprintf("%d", data.Event.TGID))
	addField("Destination", data.Event.Destination)
	addField("Port", fmt.Sprintf("%d", data.Event.Port))
	addField("Protocol", data.Event.Protocol)
	addField("Process Path", data.Event.ProcessPath)
	addField("Process SHA256", data.Event.ProcessSHA256)
	addField("First Seen", data.FirstSeen.Format("2006-01-02 15:04:05"))
	addField("Last Seen", data.LastSeen.Format("2006-01-02 15:04:05"))
	addField("Count", fmt.Sprintf("%d", data.Count))

	// Add help text
	content.WriteString("\n")
	helpStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("241")).
		Italic(true)
	content.WriteString(helpStyle.Render("Press ESC to close"))

	// Style the popup
	popupStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("86")).
		Padding(1, 2)

	popup := popupStyle.Render(content.String())

	// Center the popup
	terminalWidth := m.width
	terminalHeight := m.height

	if terminalWidth == 0 {
		terminalWidth = 80
	}
	if terminalHeight == 0 {
		terminalHeight = 24
	}

	return lipgloss.Place(terminalWidth, terminalHeight, lipgloss.Center, lipgloss.Center, popup)
}

func (m *Model) renderWhitelistPopup() string {
	if m.popupData == nil {
		return ""
	}

	data := m.popupData
	var content strings.Builder

	// Title
	titleStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("212")).
		Bold(true)
	content.WriteString(titleStyle.Render("Add to Whitelist"))
	content.WriteString("\n\n")

	// Show process information
	labelStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("86")).
		Bold(true)

	valueStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("255"))

	addField := func(label, value string) {
		content.WriteString(labelStyle.Render(label+": ") + valueStyle.Render(value) + "\n")
	}

	addField("Process", data.Event.Process)
	addField("Process Path", data.Event.ProcessPath)
	addField("SHA256", data.Event.ProcessSHA256)
	content.WriteString("\n")

	// Description input
	content.WriteString(labelStyle.Render("Description: "))
	content.WriteString("\n")
	content.WriteString(m.whitelistInput.View())
	content.WriteString("\n\n")

	// Instructions
	helpStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("241")).
		Italic(true)

	if !m.whitelistConfirming {
		content.WriteString(helpStyle.Render("Enter a description, then press ENTER to confirm"))
	} else {
		content.WriteString(helpStyle.Render("Press ENTER again to add to whitelist, or ESC to cancel"))
	}

	// Style the popup
	popupStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("212")).
		Padding(1, 2)

	popup := popupStyle.Render(content.String())

	// Center the popup
	terminalWidth := m.width
	terminalHeight := m.height

	if terminalWidth == 0 {
		terminalWidth = 80
	}
	if terminalHeight == 0 {
		terminalHeight = 24
	}

	return lipgloss.Place(terminalWidth, terminalHeight, lipgloss.Center, lipgloss.Center, popup)
}

func (m *Model) addToWhitelist() error {
	if m.popupData == nil || m.whitelistFile == "" {
		return fmt.Errorf("no whitelist file configured")
	}

	data := m.popupData
	description := strings.TrimSpace(m.whitelistInput.Value())
	if description == "" {
		description = "Added from TUI"
	}

	// Prepare the entry to append
	var entry strings.Builder
	entry.WriteString("\n")
	entry.WriteString(fmt.Sprintf("# %s\n", description))
	entry.WriteString(fmt.Sprintf("# Process: %s\n", data.Event.Process))
	entry.WriteString(fmt.Sprintf("# Path: %s\n", data.Event.ProcessPath))
	entry.WriteString(fmt.Sprintf("# Added: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	entry.WriteString(fmt.Sprintf("%s\n", data.Event.ProcessSHA256))

	// Append to whitelist file
	file, err := os.OpenFile(m.whitelistFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open whitelist file: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString(entry.String()); err != nil {
		return fmt.Errorf("failed to write to whitelist file: %w", err)
	}

	// Update the process cache's whitelist filter
	if m.processCache != nil {
		if err := m.processCache.GetWhitelistFilter().AddHash(data.Event.ProcessSHA256); err != nil {
			return fmt.Errorf("failed to add hash to filter: %w", err)
		}
	}

	return nil
}

// evictCacheIfNeeded performs size-based cache eviction (time-based is handled by timer)
func (m *Model) evictCacheIfNeeded() {
	// Size-based cleanup (run immediately if over limit)
	if len(m.connections) > m.cacheMaxSize {
		m.evictOldestEntries()
	}
}

// evictExpiredEntries removes connections that have exceeded the TTL
func (m *Model) evictExpiredEntries(now time.Time) int {
	keysToDelete := make([]string, 0)
	
	for key, conn := range m.connections {
		if now.Sub(conn.LastSeen) > m.cacheTTL {
			keysToDelete = append(keysToDelete, key)
		}
	}
	
	for _, key := range keysToDelete {
		delete(m.connections, key)
	}
	
	return len(keysToDelete)
}

// evictOldestEntries removes the oldest entries to stay within size limit
func (m *Model) evictOldestEntries() {
	if len(m.connections) <= m.cacheMaxSize {
		return
	}
	
	// Create a slice of connections with their keys for sorting
	type connectionWithKey struct {
		key  string
		conn *ConnectionData
	}
	
	connections := make([]connectionWithKey, 0, len(m.connections))
	for key, conn := range m.connections {
		connections = append(connections, connectionWithKey{key: key, conn: conn})
	}
	
	// Sort by LastSeen (oldest first)
	sort.Slice(connections, func(i, j int) bool {
		return connections[i].conn.LastSeen.Before(connections[j].conn.LastSeen)
	})
	
	// Remove the oldest entries until we're within the size limit
	entriesToRemove := len(connections) - m.cacheMaxSize
	for i := 0; i < entriesToRemove; i++ {
		delete(m.connections, connections[i].key)
	}
}
