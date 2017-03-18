package systray

func New(iconPath string, clientPath string) *Systray {
    return &Systray{_NewSystray(iconPath, clientPath)}
}

type Systray struct {
    *_Systray
}


type CallbackInfo struct {
    ItemName string
    Callback func()
    Disabled bool
    Checked bool
}

