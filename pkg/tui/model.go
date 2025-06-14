package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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

type ConnectionData struct {
	Event     *types.Event
	Count     int
	LastSeen  time.Time
	FirstSeen time.Time
}

type Model struct {
	table       table.Model
	connections map[string]*ConnectionData
	sortBy      sortColumn
	sortDesc    bool
	totalEvents int
	startTime   time.Time
	selectedRow int
	width       int
	height      int
	showPopup   bool
	popupData   *ConnectionData
}

type EventMsg struct {
	Event *types.Event
}

func NewModel() Model {
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

	m := Model{
		table:       t,
		connections: make(map[string]*ConnectionData),
		sortBy:      sortByLastSeen,
		sortDesc:    true,
		startTime:   time.Now(),
	}

	// Set initial column headers with sort indicators
	m.updateColumnHeaders()

	return m
}

func (m Model) Init() tea.Cmd {
	return nil
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

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit

		case "enter":
			if !m.showPopup {
				m.showPopup = true
				m.popupData = m.getSelectedConnection()
			}
			return m, nil

		case "esc":
			if m.showPopup {
				m.showPopup = false
				m.popupData = nil
			}
			return m, nil

		case "1":
			if !m.showPopup {
				m.sortBy = sortByProcess
				m.sortDesc = !m.sortDesc
				m.updateTable()
			}

		case "2":
			if !m.showPopup {
				m.sortBy = sortByDestination
				m.sortDesc = !m.sortDesc
				m.updateTable()
			}

		case "3":
			if !m.showPopup {
				m.sortBy = sortByPort
				m.sortDesc = !m.sortDesc
				m.updateTable()
			}

		case "4":
			if !m.showPopup {
				m.sortBy = sortByProtocol
				m.sortDesc = !m.sortDesc
				m.updateTable()
			}

		case "5":
			if !m.showPopup {
				m.sortBy = sortByFirstSeen
				m.sortDesc = !m.sortDesc
				m.updateTable()
			}

		case "6":
			if !m.showPopup {
				m.sortBy = sortByLastSeen
				m.sortDesc = !m.sortDesc
				m.updateTable()
			}

		case "7":
			if !m.showPopup {
				m.sortBy = sortByCount
				m.sortDesc = !m.sortDesc
				m.updateTable()
			}

		case "8":
			if !m.showPopup {
				m.sortBy = sortBySHA256
				m.sortDesc = !m.sortDesc
				m.updateTable()
			}

		case "r":
			if !m.showPopup {
				// Refresh - clear all data
				m.connections = make(map[string]*ConnectionData)
				m.totalEvents = 0
				m.startTime = time.Now()
				m.updateTable()
			}
		}
	}

	if !m.showPopup {
		m.table, cmd = m.table.Update(msg)
	}
	return m, cmd
}

func (m *Model) View() string {
	if m.showPopup && m.popupData != nil {
		return m.renderPopup()
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
		statsStyle.Render(fmt.Sprintf("Uptime: %v | Total Events: %d | Unique Connections: %d",
			uptime, m.totalEvents, len(m.connections)))

	b.WriteString(header + "\n\n")

	// Instructions above table
	helpStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("241")).
		Padding(0, 1)

	help := helpStyle.Render("Keys: 1-8 sort columns | r reset | enter details | q quit")
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

func (m *Model) renderPopup() string {
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

func SendEvent(event *types.Event) tea.Cmd {
	return func() tea.Msg {
		return EventMsg{Event: event}
	}
}
