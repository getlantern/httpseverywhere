package httpseverywhere

/*
type Chiroot struct {
	Chiruleset *Chiruleset `xml:" ruleset,omitempty" json:"ruleset,omitempty"`
}

type Chirule struct {
	Attr_from string `xml:" from,attr"  json:",omitempty"`
	Attr_to   string `xml:" to,attr"  json:",omitempty"`
}

type Chiruleset struct {
	Attr_name string     `xml:" name,attr"  json:",omitempty"`
	Chirule   *Chirule   `xml:" rule,omitempty" json:"rule,omitempty"`
	Chitarget *Chitarget `xml:" target,omitempty" json:"target,omitempty"`
}

type Chitarget struct {
	Attr_host string `xml:" host,attr"  json:",omitempty"`
}
*/

type Target struct {
	Host string `xml:"host,attr"`
}

type Exclusion struct {
	Pattern string `xml:"pattern,attr"`
}

type Rule struct {
	From string `xml:"from,attr"`
	To   string `xml:"to,attr"`
}

type Ruleset struct {
	Off       string      `xml:"default_off,attr"`
	Target    []Target    `xml:"target"`
	Exclusion []Exclusion `xml:"exclusion"`
	Rule      []Rule      `xml:"rule"`
}
