package theme

import "github.com/charmbracelet/lipgloss"

type Theme struct {
	Name string
	
	// Table colors
	TableHeaderBorder    lipgloss.Color
	TableHeaderForeground lipgloss.Color
	TableHeaderBackground lipgloss.Color
	TableSelectedForeground lipgloss.Color
	TableSelectedBackground lipgloss.Color
	TableBorder          lipgloss.Color
	
	// Header section colors
	HeaderForeground     lipgloss.Color
	StatsForeground      lipgloss.Color
	HelpForeground       lipgloss.Color
	
	// Popup colors
	DetailsPopupBorder   lipgloss.Color
	FilterPopupBorder lipgloss.Color
	PopupLabelForeground lipgloss.Color
	PopupValueForeground lipgloss.Color
	PopupBackground      lipgloss.Color
	
	// General colors
	TextPrimary          lipgloss.Color
	TextSecondary        lipgloss.Color
	Background           lipgloss.Color
}

var (
	// Dark theme (original colors)
	DarkTheme = Theme{
		Name: "dark",
		
		// Table
		TableHeaderBorder:       lipgloss.Color("240"),
		TableHeaderForeground:   lipgloss.Color("255"),
		TableHeaderBackground:   lipgloss.Color(""),
		TableSelectedForeground: lipgloss.Color("229"),
		TableSelectedBackground: lipgloss.Color("57"),
		TableBorder:            lipgloss.Color("240"),
		
		// Header
		HeaderForeground:       lipgloss.Color("86"),
		StatsForeground:        lipgloss.Color("243"),
		HelpForeground:         lipgloss.Color("241"),
		
		// Popups
		DetailsPopupBorder:     lipgloss.Color("86"),
		FilterPopupBorder:   lipgloss.Color("212"),
		PopupLabelForeground:   lipgloss.Color("86"),
		PopupValueForeground:   lipgloss.Color("255"),
		PopupBackground:        lipgloss.Color(""),
		
		// General
		TextPrimary:            lipgloss.Color("255"),
		TextSecondary:          lipgloss.Color("243"),
		Background:             lipgloss.Color(""),
	}
	
	// Light theme
	LightTheme = Theme{
		Name: "light",
		
		// Table
		TableHeaderBorder:       lipgloss.Color("240"),
		TableHeaderForeground:   lipgloss.Color("0"),
		TableHeaderBackground:   lipgloss.Color("252"),
		TableSelectedForeground: lipgloss.Color("255"),
		TableSelectedBackground: lipgloss.Color("24"),
		TableBorder:            lipgloss.Color("240"),
		
		// Header
		HeaderForeground:       lipgloss.Color("22"),
		StatsForeground:        lipgloss.Color("240"),
		HelpForeground:         lipgloss.Color("238"),
		
		// Popups
		DetailsPopupBorder:     lipgloss.Color("22"),
		FilterPopupBorder:   lipgloss.Color("161"),
		PopupLabelForeground:   lipgloss.Color("22"),
		PopupValueForeground:   lipgloss.Color("235"),
		PopupBackground:        lipgloss.Color("255"),
		
		// General
		TextPrimary:            lipgloss.Color("0"),
		TextSecondary:          lipgloss.Color("240"),
		Background:             lipgloss.Color("255"),
	}
	
	// Monochrome theme
	MonochromeTheme = Theme{
		Name: "monochrome",
		
		// Table
		TableHeaderBorder:       lipgloss.Color("255"),
		TableHeaderForeground:   lipgloss.Color("255"),
		TableHeaderBackground:   lipgloss.Color("0"),
		TableSelectedForeground: lipgloss.Color("0"),
		TableSelectedBackground: lipgloss.Color("255"),
		TableBorder:            lipgloss.Color("255"),
		
		// Header
		HeaderForeground:       lipgloss.Color("255"),
		StatsForeground:        lipgloss.Color("255"),
		HelpForeground:         lipgloss.Color("255"),
		
		// Popups
		DetailsPopupBorder:     lipgloss.Color("255"),
		FilterPopupBorder:   lipgloss.Color("255"),
		PopupLabelForeground:   lipgloss.Color("255"),
		PopupValueForeground:   lipgloss.Color("247"),
		PopupBackground:        lipgloss.Color("0"),
		
		// General
		TextPrimary:            lipgloss.Color("255"),
		TextSecondary:          lipgloss.Color("255"),
		Background:             lipgloss.Color("0"),
	}
	
	// Blue theme
	BlueTheme = Theme{
		Name: "blue",
		
		// Table
		TableHeaderBorder:       lipgloss.Color("4"),
		TableHeaderForeground:   lipgloss.Color("255"),
		TableHeaderBackground:   lipgloss.Color("18"),
		TableSelectedForeground: lipgloss.Color("255"),
		TableSelectedBackground: lipgloss.Color("4"),
		TableBorder:            lipgloss.Color("4"),
		
		// Header
		HeaderForeground:       lipgloss.Color("12"),
		StatsForeground:        lipgloss.Color("6"),
		HelpForeground:         lipgloss.Color("8"),
		
		// Popups
		DetailsPopupBorder:     lipgloss.Color("12"),
		FilterPopupBorder:   lipgloss.Color("5"),
		PopupLabelForeground:   lipgloss.Color("12"),
		PopupValueForeground:   lipgloss.Color("255"),
		PopupBackground:        lipgloss.Color("18"),
		
		// General
		TextPrimary:            lipgloss.Color("255"),
		TextSecondary:          lipgloss.Color("6"),
		Background:             lipgloss.Color("0"),
	}
	
	// Rainbow theme - super colorful and fun!
	RainbowTheme = Theme{
		Name: "rainbow",
		
		// Table
		TableHeaderBorder:       lipgloss.Color("201"), // Hot pink
		TableHeaderForeground:   lipgloss.Color("226"), // Bright yellow
		TableHeaderBackground:   lipgloss.Color("54"),  // Purple
		TableSelectedForeground: lipgloss.Color("0"),   // Black text
		TableSelectedBackground: lipgloss.Color("226"), // Bright yellow
		TableBorder:            lipgloss.Color("51"),   // Cyan
		
		// Header
		HeaderForeground:       lipgloss.Color("208"), // Orange
		StatsForeground:        lipgloss.Color("200"), // Pink
		HelpForeground:         lipgloss.Color("45"),  // Bright cyan
		
		// Popups
		DetailsPopupBorder:     lipgloss.Color("82"),  // Bright green
		FilterPopupBorder:   lipgloss.Color("165"), // Magenta
		PopupLabelForeground:   lipgloss.Color("220"), // Gold
		PopupValueForeground:   lipgloss.Color("87"),  // Light green
		PopupBackground:        lipgloss.Color("17"),  // Dark blue
		
		// General
		TextPrimary:            lipgloss.Color("118"), // Lime green
		TextSecondary:          lipgloss.Color("213"), // Light pink
		Background:             lipgloss.Color("16"),  // Very dark
	}
)

var availableThemes = map[string]Theme{
	"dark":       DarkTheme,
	"light":      LightTheme,
	"monochrome": MonochromeTheme,
	"blue":       BlueTheme,
	"rainbow":    RainbowTheme,
}

func GetTheme(name string) (Theme, bool) {
	theme, exists := availableThemes[name]
	return theme, exists
}

func GetAvailableThemes() []string {
	themes := make([]string, 0, len(availableThemes))
	for name := range availableThemes {
		themes = append(themes, name)
	}
	return themes
}

func GetDefaultTheme() Theme {
	return DarkTheme
}