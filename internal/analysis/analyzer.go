package analysis

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode"

	"github.com/loomtek/vellum/internal/domain"
)

// Result holds the final email analysis output including the numeric score,
// letter grade, per-category breakdown, and Vellum verification status.
type Result struct {
	Score                  int        `json:"score"`
	Grade                  string     `json:"grade"`
	Summary                string     `json:"summary"`
	IsVellumVerified       bool       `json:"is_vellum_verified"`
	VerificationDisclaimer string     `json:"verification_disclaimer"`
	Categories             []Category `json:"categories"`
}

// Category groups related checks under a named section (e.g. Security,
// Compatibility) with a summary of passed vs total checks.
type Category struct {
	ID     string  `json:"id"`
	Name   string  `json:"name"`
	Passed int     `json:"passed"`
	Total  int     `json:"total"`
	Checks []Check `json:"checks"`
}

// Check represents a single analysis rule with its pass/fail state, severity
// level, human-readable detail, and score impact when failed.
type Check struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Passed   bool   `json:"passed"`
	Skipped  bool   `json:"skipped"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
	Impact   int    `json:"impact"`
}

type locale struct{ lang string }

func newLocale(lang string) locale {
	if lang != "en" {
		lang = "es"
	}
	return locale{lang}
}

func (l locale) t(es, en string) string {
	if l.lang == "en" {
		return en
	}
	return es
}

func (l locale) tf(esf, enf string, args ...any) string {
	if l.lang == "en" {
		return fmt.Sprintf(enf, args...)
	}
	return fmt.Sprintf(esf, args...)
}

var (
	reScript        = regexp.MustCompile(`(?i)<\s*script[\s>\/]`)
	reJavascriptURL = regexp.MustCompile(`(?i)(href|src|action)\s*=\s*['"\s]*javascript\s*:`)
	reOnEvent       = regexp.MustCompile(`(?i)\s+on[a-zA-Z]{2,}\s*=\s*["']`)
	reDangerousTags = regexp.MustCompile(`(?i)<\s*(iframe|object|embed|applet)[\s>\/]`)
	reCSSExpr       = regexp.MustCompile(`(?i)expression\s*\(`)
	reDataJSURL     = regexp.MustCompile(`(?i)(src|href)\s*=\s*['"]?data:(text/html|application/javascript|text/javascript)`)
	reExternalForm  = regexp.MustCompile(`(?i)<\s*form[^>]{0,500}action\s*=\s*['"]?https?://`)
	reIPLink        = regexp.MustCompile(`(?i)https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[/\s"']`)

	reFlex      = regexp.MustCompile(`(?i)display\s*:\s*(flex|inline-flex)`)
	reGrid      = regexp.MustCompile(`(?i)display\s*:\s*(grid|inline-grid)`)
	reCSSVar    = regexp.MustCompile(`(?i)\bvar\s*\(--`)
	reFontFace  = regexp.MustCompile(`(?i)@font-face`)
	reCSSImport = regexp.MustCompile(`(?i)@import\s`)
	reExtCSS    = regexp.MustCompile(`(?i)<\s*link[^>]{0,300}rel\s*=\s*['"]?stylesheet`)
	rePosFixed  = regexp.MustCompile(`(?i)position\s*:\s*fixed`)
	reDoctype   = regexp.MustCompile(`(?i)<!DOCTYPE\s+html`)
	reCharset   = regexp.MustCompile(`(?i)<meta[^>]+(charset\s*=|http-equiv\s*=\s*['"]?content-type)[^>]*>`)

	reHTTPLinks = regexp.MustCompile(`(?i)<\s*a[^>]{0,500}href\s*=\s*['"']?https?://`)
	reImgTag    = regexp.MustCompile(`(?i)<\s*img[^>]*>`)
	reHasAlt    = regexp.MustCompile(`(?i)\balt\s*=`)
	reShortener = regexp.MustCompile(`(?i)https?://(bit\.ly|goo\.gl|t\.co|ow\.ly|tinyurl\.com|is\.gd|buff\.ly|dlvr\.it|short\.io|rb\.gy|shorturl\.at|rebrand\.ly|cutt\.ly|tiny\.cc|bl\.ink|tr\.im|snip\.ly|ift\.tt|t2m\.io)/`)

	reHiddenDisplayNone = regexp.MustCompile(`(?i)display\s*:\s*none`)
	reHiddenVisibility  = regexp.MustCompile(`(?i)visibility\s*:\s*hidden`)
	reHiddenFontSize0   = regexp.MustCompile(`(?i)font-size\s*:\s*0\s*(?:px|pt|em|rem)?(?:\s*[;}'""]|\s*$)`)
	reHiddenOpacity0    = regexp.MustCompile(`(?i)opacity\s*:\s*0(?:\.0+)?\s*(?:[;}'"\s]|$)`)
	reOffscreen         = regexp.MustCompile(`(?i)(?:left|top)\s*:\s*-\d{3,}`)

	reDeceptiveSubject = regexp.MustCompile(`(?i)^(re\s*:|r\.e\.\s*:|fwd?\s*:|fw\s*:|rv\s*:|aw\s*:)`)
	reMultipleAtSigns  = regexp.MustCompile(`@[^@,;<>]+[,;].*@`)

	reUnsubscribeBody = regexp.MustCompile(`(?i)(unsubscribe|darse\s+de\s+baja|cancelar\s+suscripci|opt.?out)`)

	reMetaColorScheme      = regexp.MustCompile(`(?i)<meta[^>]+name\s*=\s*["']?color-scheme["']?[^>]*>`)
	reDarkModeMedia        = regexp.MustCompile(`(?i)@media[^{]*prefers-color-scheme\s*:\s*dark`)
	reColorSchemeOnlyLight = regexp.MustCompile(`(?i)color-scheme\s*:\s*only\s+light`)
	reStyleAttr            = regexp.MustCompile(`(?i)style\s*=\s*["']([^"']{0,1000})["']`)
	reInlineColor          = regexp.MustCompile(`(?i)(?:^|;|\s)color\s*:\s*(#[0-9a-fA-F]{6}|#[0-9a-fA-F]{3})\b`)
	reInlineBgColor        = regexp.MustCompile(`(?i)(?:^|;|\s)background(?:-color)?\s*:\s*(#[0-9a-fA-F]{6}|#[0-9a-fA-F]{3})\b`)

	// Preview text / preheader (spam technique: invisible preheader stuffed with keywords)
	rePreviewTextPattern = regexp.MustCompile(`(?i)(class|id)\s*=\s*["'][^"']*(?:preview|preheader|preview-text|preheader-text)[^"']*["']`)

	// Mixed content: http:// images inside an otherwise https email
	reMixedContentImg = regexp.MustCompile(`(?i)<\s*img[^>]+src\s*=\s*["']?http://`)

	// Excessive punctuation in text (!!!, ???, etc.) — spam signal
	reExcessivePunct = regexp.MustCompile(`[!?]{3,}`)
)

var suspiciousExtensions = []string{".exe", ".bat", ".cmd", ".vbs", ".js", ".scr", ".pif", ".msi", ".ps1"}

// Analyze runs all analysis categories against the given email and returns a
// consolidated Result with score, grade, and per-check details.
func Analyze(e *domain.Email, lang string) Result {
	loc := newLocale(lang)
	html := e.HTMLBody
	subject := e.Subject

	categories := []Category{
		buildCategory("security", loc.t("Seguridad", "Security"), securityChecks(html, loc)),
		buildCategory("compatibility", loc.t("Compatibilidad con clientes", "Client compatibility"), compatibilityChecks(html, loc)),
		buildCategory("structure", loc.t("Estructura y cabeceras RFC", "RFC structure and headers"), structureChecks(e, loc)),
		buildCategory("deliverability", loc.t("Entregabilidad", "Deliverability"), deliverabilityChecks(e, subject, html, loc)),
		buildCategory("unsubscribe", loc.t("Desuscripción (remitentes masivos)", "Unsubscribe (bulk senders)"), unsubscribeChecks(e, html, loc)),
		buildCategory("a11y", loc.t("Accesibilidad y visualización", "Accessibility and rendering"), a11yChecks(html, loc)),
	}

	verified := checkVellumVerified(categories)
	score := computeScore(categories)

	return Result{
		Score:                  score,
		Grade:                  computeGrade(score, !verified),
		Summary:                computeSummary(score, categories, loc),
		IsVellumVerified:       verified,
		VerificationDisclaimer: vellumDisclaimer(verified, loc),
		Categories:             categories,
	}
}

func securityChecks(html string, loc locale) []Check {
	noHTML := loc.t("No aplica: el correo no contiene cuerpo HTML.", "Not applicable: the email has no HTML body.")
	hasHTML := html != ""

	checks := []Check{
		{ID: "no_script_tags", Name: loc.t("Sin etiquetas <script>", "No <script> tags"), Severity: "blocker", Impact: 20},
		{ID: "no_javascript_urls", Name: loc.t("Sin URLs javascript:", "No javascript: URLs"), Severity: "blocker", Impact: 20},
		{ID: "no_event_handlers", Name: loc.t("Sin manejadores de eventos inline (on*)", "No inline event handlers (on*)"), Severity: "warning", Impact: 12},
		{ID: "no_dangerous_tags", Name: loc.t("Sin etiquetas iframe, object o embed", "No iframe, object or embed tags"), Severity: "blocker", Impact: 12},
		{ID: "no_css_expression", Name: loc.t("Sin expresiones CSS (expression())", "No CSS expressions (expression())"), Severity: "blocker", Impact: 15},
		{ID: "no_data_js_urls", Name: loc.t("Sin URLs data: con código ejecutable", "No data: URLs with executable code"), Severity: "blocker", Impact: 15},
		{ID: "no_external_form", Name: loc.t("Sin formularios con acción a dominios externos", "No forms with external domain actions"), Severity: "warning", Impact: 6},
		{ID: "no_ip_links", Name: loc.t("Sin enlaces directos a direcciones IP", "No direct links to IP addresses"), Severity: "warning", Impact: 8},
	}

	if !hasHTML {
		for i := range checks {
			skipCheck(&checks[i], noHTML)
		}
		return checks
	}

	setCheck(&checks[0], !reScript.MatchString(html),
		loc.t("No se encontraron etiquetas <script>.", "No <script> tags found."),
		loc.t("Se encontraron etiquetas <script>. Los proveedores de correo las eliminan o bloquean el mensaje completo.",
			"Found <script> tags. Email providers strip them or block the entire message."))

	setCheck(&checks[1], !reJavascriptURL.MatchString(html),
		loc.t("No se encontraron URLs javascript:.", "No javascript: URLs found."),
		loc.t("Se encontraron URLs javascript: en atributos href/src/action. Son bloqueadas por todos los clientes de correo.",
			"Found javascript: URLs in href/src/action attributes. All email clients block these."))

	setCheck(&checks[2], !reOnEvent.MatchString(html),
		loc.t("No se encontraron manejadores de eventos inline.", "No inline event handlers found."),
		loc.t("Se encontraron atributos on* (onclick, onload, onerror…). Los clientes los eliminan por seguridad sin previo aviso.",
			"Found on* attributes (onclick, onload, onerror…). Email clients strip them silently for security."))

	setCheck(&checks[3], !reDangerousTags.MatchString(html),
		loc.t("No se encontraron etiquetas iframe, object ni embed.", "No iframe, object or embed tags found."),
		loc.t("Se detectaron etiquetas iframe, object o embed. Gmail, Outlook y los demás proveedores las eliminan completamente del mensaje.",
			"Found iframe, object or embed tags. Gmail, Outlook and other providers remove them completely from the message."))

	setCheck(&checks[4], !reCSSExpr.MatchString(html),
		loc.t("No se encontraron expresiones CSS.", "No CSS expressions found."),
		loc.t("Se encontró expression() en CSS. Es un vector de ataque conocido que activa filtros antispam de forma inmediata.",
			"Found expression() in CSS. This is a known attack vector that immediately triggers spam filters."))

	setCheck(&checks[5], !reDataJSURL.MatchString(html),
		loc.t("No se encontraron URLs data: con código ejecutable.", "No data: URLs with executable code found."),
		loc.t("Se encontraron URLs data:text/html o data:application/javascript. Son bloqueadas por todos los filtros de seguridad modernos.",
			"Found data:text/html or data:application/javascript URLs. All modern security filters block these."))

	setCheck(&checks[6], !reExternalForm.MatchString(html),
		loc.t("No se encontraron formularios con acción hacia dominios externos.", "No forms with actions pointing to external domains."),
		loc.t("Se encontró un <form> apuntando a una URL externa. Gmail y Outlook marcan esto como sospechoso de phishing.",
			"Found a <form> pointing to an external URL. Gmail and Outlook flag this as suspicious phishing activity."))

	setCheck(&checks[7], !reIPLink.MatchString(html),
		loc.t("No se encontraron enlaces directos a direcciones IP.", "No direct links to IP addresses found."),
		loc.t("Se encontraron enlaces que apuntan directamente a IPs (ej. http://1.2.3.4/…). Los filtros antispam y antiphishing los bloquean sistemáticamente.",
			"Found links pointing directly to IP addresses (e.g. http://1.2.3.4/…). Spam and phishing filters systematically block these."))

	return checks
}

func compatibilityChecks(html string, loc locale) []Check {
	noHTML := loc.t("No aplica: el correo no contiene cuerpo HTML.", "Not applicable: the email has no HTML body.")

	checks := []Check{
		{ID: "no_flexbox", Name: loc.t("Sin CSS Flexbox", "No CSS Flexbox"), Severity: "warning", Impact: 6},
		{ID: "no_grid", Name: loc.t("Sin CSS Grid", "No CSS Grid"), Severity: "warning", Impact: 6},
		{ID: "no_css_vars", Name: loc.t("Sin variables CSS (var())", "No CSS variables (var())"), Severity: "info", Impact: 3},
		{ID: "no_font_face", Name: loc.t("Sin @font-face", "No @font-face"), Severity: "info", Impact: 3},
		{ID: "no_css_import", Name: loc.t("Sin @import en CSS", "No @import in CSS"), Severity: "warning", Impact: 4},
		{ID: "no_external_css", Name: loc.t("Sin hojas de estilo externas", "No external stylesheets"), Severity: "warning", Impact: 7},
		{ID: "no_position_fixed", Name: loc.t("Sin position: fixed en CSS", "No position: fixed in CSS"), Severity: "info", Impact: 3},
		{ID: "has_doctype", Name: loc.t("Declaración DOCTYPE presente", "DOCTYPE declaration present"), Severity: "info", Impact: 3},
		{ID: "has_charset", Name: loc.t("Declaración de codificación (charset) presente", "Character encoding (charset) declaration present"), Severity: "warning", Impact: 4},
	}

	if html == "" {
		for i := range checks {
			skipCheck(&checks[i], noHTML)
		}
		return checks
	}

	setCheck(&checks[0], !reFlex.MatchString(html),
		loc.t("No se usa Flexbox.", "Flexbox not used."),
		loc.t("Se detectó display:flex/inline-flex. Outlook 2007–2019 no soporta Flexbox y renderizará el layout de forma incorrecta.",
			"Found display:flex/inline-flex. Outlook 2007–2019 does not support Flexbox and will render the layout incorrectly."))

	setCheck(&checks[1], !reGrid.MatchString(html),
		loc.t("No se usa CSS Grid.", "CSS Grid not used."),
		loc.t("Se detectó display:grid/inline-grid. CSS Grid no está soportado en Outlook ni en la mayoría de clientes de correo de escritorio.",
			"Found display:grid/inline-grid. CSS Grid is not supported in Outlook or most desktop email clients."))

	setCheck(&checks[2], !reCSSVar.MatchString(html),
		loc.t("No se usan variables CSS.", "CSS variables not used."),
		loc.t("Se detectó var(--). Las variables CSS no están soportadas en Outlook ni en varios clientes webmail.",
			"Found var(--). CSS variables are not supported in Outlook or several webmail clients."))

	setCheck(&checks[3], !reFontFace.MatchString(html),
		loc.t("No se usan fuentes web personalizadas.", "No custom web fonts used."),
		loc.t("Se detectó @font-face. Solo Gmail y Apple Mail soportan fuentes web; el resto cae a un fallback genérico que puede alterar el diseño.",
			"Found @font-face. Only Gmail and Apple Mail support web fonts; others fall back to a generic font that may alter the design."))

	setCheck(&checks[4], !reCSSImport.MatchString(html),
		loc.t("No se usa @import en CSS.", "@import not used in CSS."),
		loc.t("Se detectó @import. Los clientes de correo ignoran las hojas importadas por lo que el correo puede quedar sin estilos.",
			"Found @import. Email clients ignore imported stylesheets, so the email may render without styles."))

	setCheck(&checks[5], !reExtCSS.MatchString(html),
		loc.t("No se referencian hojas de estilo externas.", "No external stylesheets referenced."),
		loc.t("Se detectó <link rel=\"stylesheet\">. Los clientes de correo bloquean hojas externas por seguridad; los estilos no se aplicarán.",
			"Found <link rel=\"stylesheet\">. Email clients block external stylesheets for security; styles will not be applied."))

	setCheck(&checks[6], !rePosFixed.MatchString(html),
		loc.t("No se usa position: fixed.", "position: fixed not used."),
		loc.t("Se detectó position:fixed. No está soportado en la mayoría de clientes de correo y puede ocultar u oscurecer contenido.",
			"Found position:fixed. Not supported in most email clients and can hide or obscure content."))

	setCheck(&checks[7], reDoctype.MatchString(html),
		loc.t("El HTML incluye declaración DOCTYPE.", "HTML includes DOCTYPE declaration."),
		loc.t("No se encontró <!DOCTYPE html>. Sin DOCTYPE los clientes de correo activan el modo quirks, lo que puede deformar el layout.",
			"No <!DOCTYPE html> found. Without DOCTYPE, email clients activate quirks mode, which may distort the layout."))

	setCheck(&checks[8], reCharset.MatchString(html),
		loc.t("El HTML declara la codificación de caracteres.", "HTML declares the character encoding."),
		loc.t("No se encontró <meta charset> ni Content-Type meta. Sin esta declaración los caracteres especiales (tildes, ñ…) pueden mostrarse corruptos.",
			"No <meta charset> or Content-Type meta found. Without this declaration, special characters (accents, ñ…) may appear corrupted."))

	return checks
}

func structureChecks(e *domain.Email, loc locale) []Check {
	checks := []Check{
		{ID: "has_html_body", Name: loc.t("Contiene versión HTML", "Contains HTML version"), Severity: "warning", Impact: 8},
		{ID: "has_text_body", Name: loc.t("Contiene versión texto plano", "Contains plain text version"), Severity: "warning", Impact: 8},
		{ID: "text_body_content", Name: loc.t("El texto plano tiene contenido real", "Plain text has real content"), Severity: "warning", Impact: 5},
		{ID: "has_subject", Name: loc.t("El asunto no está vacío", "Subject is not empty"), Severity: "warning", Impact: 6},
		{ID: "subject_length", Name: loc.t("Longitud del asunto adecuada (6–78 caracteres)", "Adequate subject length (6–78 characters)"), Severity: "info", Impact: 3},
		{ID: "has_date", Name: loc.t("Cabecera Date presente (RFC 2822)", "Date header present (RFC 2822)"), Severity: "warning", Impact: 5},
		{ID: "has_message_id", Name: loc.t("Contiene Message-ID (RFC 5322)", "Contains Message-ID (RFC 5322)"), Severity: "blocker", Impact: 10},
		{ID: "unique_headers", Name: loc.t("Sin cabeceras singulares duplicadas (RFC 5322)", "No duplicate singular headers (RFC 5322)"), Severity: "warning", Impact: 6},
		{ID: "has_from_name", Name: loc.t("El remitente incluye nombre visible", "Sender includes display name"), Severity: "warning", Impact: 5},
		{ID: "single_from_address", Name: loc.t("El campo From tiene exactamente una dirección", "From field has exactly one address"), Severity: "blocker", Impact: 8},
	}

	hasHTML := e.HTMLBody != ""
	setCheck(&checks[0], hasHTML,
		loc.t("El correo incluye versión HTML.", "Email includes HTML version."),
		loc.t("El correo no tiene cuerpo HTML. Sin HTML el formato es muy limitado y puede parecer poco profesional o automatizado.",
			"Email has no HTML body. Without HTML, formatting is very limited and may appear unprofessional or automated."))

	hasText := e.TextBody != ""
	setCheck(&checks[1], hasText,
		loc.t("El correo incluye versión texto plano.", "Email includes plain text version."),
		loc.t("El correo no tiene versión texto plano. Siempre se recomienda un fallback en texto para clientes que no renderizan HTML y para los filtros antispam.",
			"Email has no plain text version. A text fallback is always recommended for clients that don't render HTML and for spam filters."))

	if !hasText {
		skipCheck(&checks[2], loc.t("No aplica: el correo no tiene cuerpo de texto plano.", "Not applicable: the email has no plain text body."))
	} else {
		words := len(strings.Fields(e.TextBody))
		setCheck(&checks[2], words >= 5,
			loc.tf("El texto plano tiene contenido legible (%d palabras).", "Plain text has readable content (%d words).", words),
			loc.t("El cuerpo de texto plano existe pero está vacío o contiene solo espacios. Los filtros antispam penalizan los correos con texto plano vacío.",
				"The plain text body exists but is empty or contains only spaces. Spam filters penalize emails with empty plain text."))
	}

	hasSubject := strings.TrimSpace(e.Subject) != ""
	setCheck(&checks[3], hasSubject,
		loc.t("El asunto está presente.", "Subject is present."),
		loc.t("El correo no tiene asunto. Los filtros antispam penalizan fuertemente los correos sin asunto.",
			"Email has no subject. Spam filters heavily penalize emails without a subject."))

	subjectLen := len([]rune(strings.TrimSpace(e.Subject)))
	if !hasSubject {
		skipCheck(&checks[4], loc.t("No se puede evaluar: el asunto está vacío.", "Cannot evaluate: subject is empty."))
	} else {
		setCheck(&checks[4], subjectLen >= 6 && subjectLen <= 78,
			loc.tf("El asunto tiene %d caracteres, dentro del rango óptimo.", "Subject has %d characters, within the optimal range.", subjectLen),
			loc.tf("El asunto tiene %d caracteres. El rango óptimo es 6–78 para evitar truncamiento en Gmail, Outlook y clientes móviles.",
				"Subject has %d characters. The optimal range is 6–78 to avoid truncation in Gmail, Outlook, and mobile clients.", subjectLen))
	}

	hasDate := firstHeader(e.RawHeaders, "date") != ""
	setCheck(&checks[5], hasDate,
		loc.t("La cabecera Date está presente.", "The Date header is present."),
		loc.t("El correo no tiene cabecera Date. Es obligatoria según RFC 2822; su ausencia genera desconfianza en los filtros antispam.",
			"Email is missing the Date header. Required by RFC 2822; its absence raises red flags in spam filters."))

	setCheck(&checks[6], strings.TrimSpace(e.MessageID) != "",
		loc.t("El correo tiene Message-ID.", "Email has Message-ID."),
		loc.t("El correo no tiene Message-ID. Es obligatorio según RFC 5322 y su ausencia activa filtros antispam en la mayoría de proveedores.",
			"Email has no Message-ID. Required by RFC 5322; its absence triggers spam filters in most providers."))

	duplicated := findDuplicateSingularHeaders(e.RawHeaders)
	setCheck(&checks[7], len(duplicated) == 0,
		loc.t("Todas las cabeceras singulares aparecen exactamente una vez.", "All singular headers appear exactly once."),
		loc.tf("Las cabeceras %s aparecen más de una vez. RFC 5322 exige que estas cabeceras sean únicas; los filtros antispam rechazan correos malformados.",
			"The headers %s appear more than once. RFC 5322 requires these headers to be unique; spam filters reject malformed messages.",
			strings.Join(duplicated, ", ")))

	hasFromName := strings.Contains(e.From, "<") && strings.Contains(e.From, ">")
	setCheck(&checks[8], hasFromName,
		loc.t("El campo From incluye nombre visible del remitente.", "The From field includes a visible sender name."),
		loc.t("El campo From solo contiene la dirección sin nombre visible (ej. solo \"usuario@dominio.com\"). Incluir un nombre (ej. \"Equipo Acme <info@acme.com>\") mejora la tasa de apertura y reduce sospechas de spam.",
			"The From field contains only the email address without a display name (e.g. just \"user@domain.com\"). Including a name (e.g. \"Acme Team <info@acme.com>\") improves open rates and reduces spam suspicion."))

	rawFrom := firstHeader(e.RawHeaders, "from")
	singleFrom := !reMultipleAtSigns.MatchString(rawFrom)
	setCheck(&checks[9], singleFrom,
		loc.t("El campo From contiene exactamente una dirección.", "The From field contains exactly one address."),
		loc.t("El campo From contiene múltiples direcciones. RFC 5322 exige que From tenga una única dirección de autor; los proveedores pueden rechazar o marcar el correo.",
			"The From field contains multiple addresses. RFC 5322 requires From to have a single author address; providers may reject or flag the message."))

	return checks
}

func deliverabilityChecks(e *domain.Email, subject, html string, loc locale) []Check {
	noHTML := loc.t("No aplica: el correo no contiene HTML.", "Not applicable: the email has no HTML body.")
	noSubject := loc.t("No aplica: el asunto está vacío.", "Not applicable: subject is empty.")

	checks := []Check{
		{ID: "no_spam_triggers", Name: loc.t("Contenido sin indicadores de spam", "Content without spam indicators"), Severity: "warning", Impact: 8},
		{ID: "subject_not_allcaps", Name: loc.t("El asunto no está en mayúsculas", "Subject not in all caps"), Severity: "warning", Impact: 6},
		{ID: "no_excessive_exclamation", Name: loc.t("Sin exceso de exclamaciones en el asunto", "No excessive exclamation marks in subject"), Severity: "info", Impact: 3},
		{ID: "no_deceptive_subject", Name: loc.t("Asunto sin Re:/Fwd: engañoso", "Subject without deceptive Re:/Fwd:"), Severity: "blocker", Impact: 10},
		{ID: "no_emoji_from_name", Name: loc.t("Sin emojis en el nombre del remitente", "No emojis in sender display name"), Severity: "blocker", Impact: 8},
		{ID: "no_hidden_content", Name: loc.t("Sin contenido HTML oculto", "No hidden HTML content"), Severity: "blocker", Impact: 15},
		{ID: "no_suspicious_attachments", Name: loc.t("Sin adjuntos con extensiones peligrosas", "No attachments with dangerous extensions"), Severity: "warning", Impact: 10},
		{ID: "reasonable_link_count", Name: loc.t("Cantidad de enlaces razonable (≤ 25)", "Reasonable link count (≤ 25)"), Severity: "info", Impact: 3},
		{ID: "no_url_shorteners", Name: loc.t("Sin acortadores de URL", "No URL shorteners"), Severity: "warning", Impact: 6},
		{ID: "images_have_alt", Name: loc.t("Todas las imágenes tienen atributo alt", "All images have alt attribute"), Severity: "info", Impact: 4},
		{ID: "html_size_ok", Name: loc.t("Tamaño del HTML menor a 100 KB", "HTML size below 100 KB"), Severity: "warning", Impact: 5},
		{ID: "no_size_excess", Name: loc.t("Tamaño del mensaje aceptable (< 10 MB)", "Acceptable message size (< 10 MB)"), Severity: "warning", Impact: 5},
		// New checks
		{ID: "no_excessive_body_punctuation", Name: loc.t("Sin puntuación excesiva en el cuerpo (!!!, ???)", "No excessive body punctuation (!!!, ???)"), Severity: "info", Impact: 3},
		{ID: "no_mixed_content_images", Name: loc.t("Sin imágenes mixtas HTTP dentro de correo HTTPS", "No mixed-content HTTP images inside HTTPS email"), Severity: "warning", Impact: 5},
		{ID: "no_preheader_stuffing", Name: loc.t("Sin relleno de texto en el preencabezado", "No preheader text stuffing"), Severity: "warning", Impact: 5},
	}

	subjectTrimmed := strings.TrimSpace(subject)

	// Check 0: clasificación Bayesiana sobre asunto + cuerpo de texto
	analyzeText := strings.TrimSpace(subjectTrimmed + " " + e.TextBody)
	if activeSpamModel == nil {
		skipCheck(&checks[0], loc.t(
			"No aplica: modelo de clasificación no disponible.",
			"Not applicable: classification model not available.",
		))
	} else if analyzeText == "" {
		skipCheck(&checks[0], loc.t(
			"No aplica: el correo no tiene contenido de texto para analizar.",
			"Not applicable: the email has no text content to analyze.",
		))
	} else {
		isSpam, prob, triggers := AnalyzeSpamProbability(analyzeText)
		if isSpam {
			trigStr := strings.Join(triggers, ", ")
			setCheck(&checks[0], false, "",
				loc.tf(
					"El contenido del correo tiene un %.0f%% de probabilidad de ser marcado como spam. Palabras detectadas: [%s].",
					"Email content has a %.0f%% probability of being flagged as spam. Detected words: [%s].",
					prob*100, trigStr,
				))
		} else {
			setCheck(&checks[0], true,
				loc.tf(
					"El contenido no presenta indicadores de spam (probabilidad: %.0f%%).",
					"Content shows no spam indicators (probability: %.0f%%).",
					prob*100,
				), "")
		}
	}

	// Checks 1-3: dependen del asunto
	if subjectTrimmed == "" {
		skipCheck(&checks[1], noSubject)
		skipCheck(&checks[2], noSubject)
		skipCheck(&checks[3], noSubject)
	} else {

		setCheck(&checks[1], !isAllCaps(subjectTrimmed),
			loc.t("El asunto no está escrito en mayúsculas.", "Subject is not written in all caps."),
			loc.t("El asunto está en mayúsculas. Esto activa filtros antispam y genera desconfianza en el destinatario.",
				"Subject is written in all caps. This triggers spam filters and creates distrust in recipients."))

		excCount := strings.Count(subject, "!")
		setCheck(&checks[2], excCount <= 1,
			loc.t("El asunto no tiene exceso de signos de exclamación.", "Subject does not have excessive exclamation marks."),
			loc.tf("El asunto contiene %d signos de exclamación. Más de uno activa filtros de spam.",
				"Subject contains %d exclamation marks. More than one triggers spam filters.", excCount))

		isDeceptive := reDeceptiveSubject.MatchString(subjectTrimmed) && firstHeader(e.RawHeaders, "in-reply-to") == ""
		setCheck(&checks[3], !isDeceptive,
			loc.t("El asunto no usa Re:/Fwd: de forma engañosa.", "Subject does not use deceptive Re:/Fwd:."),
			loc.t("El asunto empieza con Re: o Fwd: pero no es una respuesta real (no hay cabecera In-Reply-To). Google y Microsoft marcan esta práctica como engañosa.",
				"Subject starts with Re: or Fwd: but is not a real reply (no In-Reply-To header). Google and Microsoft flag this practice as deceptive."))
	}

	fromName := extractFromDisplayName(e.From)
	setCheck(&checks[4], !containsEmoji(fromName),
		loc.t("El nombre del remitente no contiene emojis.", "Sender display name contains no emojis."),
		loc.t("El nombre visible del remitente contiene emojis. Google marca esta práctica como intento de imitar verificaciones o emblemas gráficos, lo que activa filtros antispam.",
			"The sender's display name contains emojis. Google flags this as an attempt to mimic verification badges or graphic elements, triggering spam filters."))

	if html == "" {
		skipCheck(&checks[5], noHTML)
	} else {
		hiddenFound := reHiddenDisplayNone.MatchString(html) ||
			reHiddenVisibility.MatchString(html) ||
			reHiddenFontSize0.MatchString(html) ||
			reHiddenOpacity0.MatchString(html) ||
			reOffscreen.MatchString(html)
		setCheck(&checks[5], !hiddenFound,
			loc.t("No se detectó contenido HTML oculto.", "No hidden HTML content detected."),
			loc.t("Se detectaron técnicas de ocultación de contenido (display:none, visibility:hidden, font-size:0, opacity:0 o posicionamiento fuera de pantalla). Google penaliza severamente esta práctica porque se usa para ocultar texto de spam.",
				"Hidden content techniques were detected (display:none, visibility:hidden, font-size:0, opacity:0 or off-screen positioning). Google severely penalizes this because it is used to hide spam text."))
	}

	suspFound := ""
	for _, att := range e.Attachments {
		lower := strings.ToLower(att.Filename)
		for _, ext := range suspiciousExtensions {
			if strings.HasSuffix(lower, ext) {
				suspFound = att.Filename
				break
			}
		}
		if suspFound != "" {
			break
		}
	}
	setCheck(&checks[6], suspFound == "",
		loc.t("No se encontraron adjuntos con extensiones peligrosas.", "No attachments with dangerous extensions found."),
		loc.tf("El adjunto \"%s\" tiene una extensión bloqueada por los principales proveedores de correo.",
			"The attachment \"%s\" has an extension blocked by major email providers.", suspFound))

	if html == "" {
		skipCheck(&checks[7], noHTML)
		skipCheck(&checks[8], noHTML)
		skipCheck(&checks[9], noHTML)
		skipCheck(&checks[10], noHTML)
	} else {
		linkCount := len(reHTTPLinks.FindAllString(html, -1))
		setCheck(&checks[7], linkCount <= 25,
			loc.tf("Número de enlaces: %d (máximo recomendado: 25).", "Link count: %d (recommended maximum: 25).", linkCount),
			loc.tf("Se encontraron %d enlaces. Un número alto de URLs es una señal de spam para los filtros automáticos.",
				"Found %d links. A high number of URLs is a spam signal for automatic filters.", linkCount))

		setCheck(&checks[8], !reShortener.MatchString(html),
			loc.t("No se encontraron acortadores de URL.", "No URL shorteners found."),
			loc.t("Se detectó un acortador de URL (bit.ly, goo.gl, tinyurl…). Los filtros antispam los penalizan porque ocultan el destino real del enlace.",
				"A URL shortener was detected (bit.ly, goo.gl, tinyurl…). Spam filters penalize these because they hide the real destination."))

		imgs := reImgTag.FindAllString(html, -1)
		imgsWithoutAlt := 0
		for _, img := range imgs {
			if !reHasAlt.MatchString(img) {
				imgsWithoutAlt++
			}
		}
		if len(imgs) == 0 {
			skipCheck(&checks[9], loc.t("No aplica: el correo no contiene imágenes.", "Not applicable: the email contains no images."))
		} else {
			setCheck(&checks[9], imgsWithoutAlt == 0,
				loc.tf("Todas las imágenes (%d) tienen atributo alt.", "All images (%d) have alt attribute.", len(imgs)),
				loc.tf("%d de %d imagen(es) no tienen atributo alt. Las imágenes sin alt son penalizadas por filtros antispam y son inaccesibles.",
					"%d of %d image(s) are missing the alt attribute. Images without alt are penalized by spam filters and are inaccessible.", imgsWithoutAlt, len(imgs)))
		}

		htmlSize := len(html)
		const maxHTMLSize = 100 * 1024
		setCheck(&checks[10], htmlSize < maxHTMLSize,
			loc.tf("Tamaño del HTML: %s (límite: 100 KB).", "HTML size: %s (limit: 100 KB).", formatBytes(int64(htmlSize))),
			loc.tf("El HTML pesa %s. Gmail recorta los mensajes con HTML superior a 100 KB y muestra un enlace \"Ver mensaje completo\".",
				"HTML size is %s. Gmail clips messages with HTML over 100 KB and shows a \"View entire message\" link.", formatBytes(int64(htmlSize))))
	}

	const maxSize = 10 * 1024 * 1024
	setCheck(&checks[11], e.Size < maxSize,
		loc.tf("Tamaño del mensaje: %s.", "Message size: %s.", formatBytes(e.Size)),
		loc.tf("El mensaje pesa %s. Los mensajes superiores a 10 MB suelen ser rechazados o bloqueados por los servidores de destino.",
			"Message size is %s. Messages over 10 MB are often rejected or blocked by destination servers.", formatBytes(e.Size)))

	// Check 12: excessive body punctuation (!!!, ???)
	bodyText := e.TextBody
	if bodyText == "" {
		bodyText = html
	}
	excessivePunct := reExcessivePunct.FindString(bodyText)
	if bodyText == "" {
		skipCheck(&checks[12], loc.t("No aplica: el correo no tiene contenido de texto.", "Not applicable: the email has no text content."))
	} else {
		setCheck(&checks[12], excessivePunct == "",
			loc.t("El cuerpo no contiene puntuación excesiva.", "The body does not contain excessive punctuation."),
			loc.t("Se encontraron secuencias de puntuación excesiva (!!!, ???, etc.) en el contenido. Los filtros antispam de Gmail, Outlook y Yahoo penalizan este patrón porque es característico del spam de ventas agresivo.",
				"Excessive punctuation sequences (!!!, ???, etc.) were found in the content. Gmail, Outlook, and Yahoo spam filters penalize this pattern as it is characteristic of aggressive sales spam."))
	}

	// Check 13: mixed content — http:// images inside an email served over https
	if html == "" {
		skipCheck(&checks[13], noHTML)
	} else {
		hasMixed := reMixedContentImg.MatchString(html)
		setCheck(&checks[13], !hasMixed,
			loc.t("No se detectaron imágenes con contenido mixto (HTTP).", "No mixed-content (HTTP) images detected."),
			loc.t("Se encontraron imágenes con src http:// en un correo servido por HTTPS. Los clientes de correo bloquean estas imágenes y muestran advertencias de seguridad al destinatario.",
				"Found img tags with src http:// inside an HTTPS email. Email clients block these images and display security warnings to the recipient."))
	}

	// Check 14: preheader/preview-text element present (good practice) but check for hidden stuffing
	if html == "" {
		skipCheck(&checks[14], noHTML)
	} else {
		hasPreheader := rePreviewTextPattern.MatchString(html)
		// Preheader exists — check if it contains hidden content (stuffing)
		if hasPreheader {
			// Check if hidden techniques are applied to the preheader element — overly broad check on the whole document is acceptable here
			hiddenNearPreheader := (reHiddenDisplayNone.MatchString(html) || reHiddenVisibility.MatchString(html) || reHiddenFontSize0.MatchString(html) || reHiddenOpacity0.MatchString(html)) && hasPreheader
			setCheck(&checks[14], !hiddenNearPreheader,
				loc.t("Se encontró un elemento de preencabezado sin técnicas de ocultación aparentes.", "A preheader element was found without apparent hiding techniques."),
				loc.t("Se detectó un elemento de preencabezado (preheader/preview-text) combinado con técnicas de ocultación de contenido. Rellenar el preencabezado con texto invisible es una táctica usada para manipular el texto de vista previa en los clientes de correo y es penalizada por los filtros antispam.",
					"A preheader/preview-text element was detected combined with content hiding techniques. Stuffing the preheader with invisible text is a tactic used to manipulate the preview text in email clients and is penalized by spam filters."))
		} else {
			setCheck(&checks[14], false,
				"",
				loc.t("No se encontró un elemento de preencabezado (class/id preheader o preview-text). Añadir un preencabezado visible mejora la tasa de apertura y evita que los clientes de correo muestren el primer texto del HTML como vista previa.",
					"No preheader/preview-text element was found (class/id preheader or preview-text). Adding a visible preheader improves open rates and prevents email clients from showing the first HTML text as the preview."))
		}
	}

	return checks
}

func unsubscribeChecks(e *domain.Email, html string, loc locale) []Check {
	checks := []Check{
		{ID: "has_list_unsubscribe", Name: loc.t("Cabecera List-Unsubscribe presente", "List-Unsubscribe header present"), Severity: "info", Impact: 2},
		{ID: "has_one_click_unsubscribe", Name: loc.t("Desuscripción con un clic (RFC 8058)", "One-click unsubscribe (RFC 8058)"), Severity: "info", Impact: 2},
		{ID: "has_unsubscribe_body", Name: loc.t("Enlace de desuscripción en el cuerpo", "Unsubscribe link in body"), Severity: "info", Impact: 2},
	}

	if isTransactionalEmail(e) {
		skipMsg := loc.t(
			"No aplica: El correo ha sido detectado como transaccional. Las directrices RFC y de proveedores no exigen cabeceras List-Unsubscribe en este tipo de mensajes.",
			"Not applicable: The email has been detected as transactional. RFC and provider guidelines do not require List-Unsubscribe headers for this type of message.",
		)
		for i := range checks {
			skipCheck(&checks[i], skipMsg)
		}
		return checks
	}

	bulkNote := loc.t(
		"Requerido por Google, Microsoft y Apple para remitentes masivos (>5.000 mensajes/día).",
		"Required by Google, Microsoft, and Apple for bulk senders (>5,000 messages/day).",
	)

	unsubHeader := firstHeader(e.RawHeaders, "list-unsubscribe")
	hasUnsubHeader := unsubHeader != ""
	setCheck(&checks[0], hasUnsubHeader,
		loc.t("Cabecera List-Unsubscribe presente.", "List-Unsubscribe header present."),
		loc.tf("No se encontró la cabecera List-Unsubscribe. %s",
			"List-Unsubscribe header not found. %s", bulkNote))

	unsubPost := firstHeader(e.RawHeaders, "list-unsubscribe-post")
	hasOneClick := strings.Contains(strings.ToLower(unsubPost), "list-unsubscribe=one-click")
	setCheck(&checks[1], hasOneClick,
		loc.t("Cabecera List-Unsubscribe-Post con valor One-Click presente.", "List-Unsubscribe-Post header with One-Click value present."),
		loc.tf("No se encontró List-Unsubscribe-Post: List-Unsubscribe=One-Click. %s Desde febrero de 2024, Gmail y Yahoo requieren esta cabecera para desuscripción con un clic.",
			"List-Unsubscribe-Post: List-Unsubscribe=One-Click not found. %s Since February 2024, Gmail and Yahoo require this header for one-click unsubscribe.", bulkNote))

	if html == "" {
		skipCheck(&checks[2], loc.t("No aplica: el correo no contiene cuerpo HTML.", "Not applicable: the email has no HTML body."))
	} else {
		hasUnsubBody := reUnsubscribeBody.MatchString(html)
		setCheck(&checks[2], hasUnsubBody,
			loc.t("Se encontró enlace o texto de desuscripción en el cuerpo del correo.", "Unsubscribe link or text found in the email body."),
			loc.tf("No se encontró enlace o texto de desuscripción en el cuerpo HTML. %s Los tres grandes proveedores exigen que sea fácilmente visible para el usuario.",
				"No unsubscribe link or text found in the HTML body. %s All three major providers require it to be easily visible to the user.", bulkNote))
	}

	return checks
}

func isTransactionalEmail(e *domain.Email) bool {
	if strings.EqualFold(firstHeader(e.RawHeaders, "x-vellum-type"), "transactional") {
		return true
	}
	subject := strings.ToLower(e.Subject)
	transactionalKeywords := []string{
		"reset", "password", "recuperación", "código", "code",
		"welcome", "bienvenido", "verify", "verificar",
	}
	for _, kw := range transactionalKeywords {
		if strings.Contains(subject, kw) {
			return true
		}
	}
	return false
}

func a11yChecks(html string, loc locale) []Check {
	noHTML := loc.t("No aplica: el correo no contiene cuerpo HTML.", "Not applicable: the email has no HTML body.")

	checks := []Check{
		{ID: "dark_mode_support", Name: loc.t("Soporte para modo oscuro", "Dark mode support"), Severity: "info", Impact: 3},
		{ID: "text_contrast", Name: loc.t("Contraste de texto adecuado (WCAG básico)", "Adequate text contrast (basic WCAG)"), Severity: "info", Impact: 6},
		{ID: "dark_mode_opt_out", Name: loc.t("Opción para evitar inversión forzada (color-scheme: only light)", "Forced dark mode opt-out (color-scheme: only light)"), Severity: "info", Impact: 2},
	}

	if html == "" {
		for i := range checks {
			skipCheck(&checks[i], noHTML)
		}
		return checks
	}

	metaTag := reMetaColorScheme.FindString(html)
	hasDarkMeta := metaTag != "" && strings.Contains(strings.ToLower(metaTag), "dark")
	hasDarkMedia := reDarkModeMedia.MatchString(html)
	setCheck(&checks[0], hasDarkMeta || hasDarkMedia,
		loc.t("El HTML incluye soporte explícito para modo oscuro.", "The HTML includes explicit dark mode support."),
		loc.t("No se detectaron etiquetas meta ni media queries para modo oscuro. Los clientes de correo forzarán una inversión de colores que podría romper tu diseño.",
			"No meta tags or media queries for dark mode were detected. Email clients will force color inversion which could break your design."))

	lowContrast := findLowContrastPairs(html)
	if lowContrast {
		setCheck(&checks[1], false,
			"",
			loc.t("Se encontraron elementos con colores de texto y fondo con bajo contraste. Esto dificulta la lectura y reduce la accesibilidad del correo.",
				"Elements with low contrast between text and background colors were found. This hinders readability and reduces email accessibility."))
	} else {
		setCheck(&checks[1], true,
			loc.t("El contraste de colores analizado cumple con estándares de legibilidad básicos.", "The analyzed color contrast meets basic legibility standards."),
			"")
	}

	// Check 2: color-scheme: only light — tells supporting clients NOT to apply dark mode inversion
	hasOnlyLight := reColorSchemeOnlyLight.MatchString(html)
	setCheck(&checks[2], hasOnlyLight,
		loc.t("El correo declara color-scheme: only light para evitar la inversión automática de colores.", "The email declares color-scheme: only light to prevent automatic color inversion."),
		loc.t("No se encontró la declaración color-scheme: only light. Los clientes que soportan este valor (Samsung Mail, algunos builds de Outlook) respetarán el diseño original y no aplicarán inversión de colores. Combínalo con el soporte de modo oscuro vía media query para una estrategia completa.",
			"The color-scheme: only light declaration was not found. Clients that support this value (Samsung Mail, some Outlook builds) will respect the original design and not apply color inversion. Combine it with dark mode support via media query for a complete strategy."))

	return checks
}

func findLowContrastPairs(html string) bool {
	styles := reStyleAttr.FindAllStringSubmatch(html, -1)
	for _, m := range styles {
		if len(m) < 2 {
			continue
		}
		style := m[1]
		colorMatch := reInlineColor.FindStringSubmatch(style)
		bgMatch := reInlineBgColor.FindStringSubmatch(style)
		if len(colorMatch) < 2 || len(bgMatch) < 2 {
			continue
		}
		l1, ok1 := hexToLuminance(colorMatch[1])
		l2, ok2 := hexToLuminance(bgMatch[1])
		if !ok1 || !ok2 {
			continue
		}
		if wcagContrastRatio(l1, l2) < 4.5 {
			return true
		}
	}
	return false
}

func parseHexNibble(c byte) uint8 {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

func hexToLuminance(hex string) (float64, bool) {
	hex = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(hex), "#"))
	if len(hex) == 3 {
		hex = string([]byte{hex[0], hex[0], hex[1], hex[1], hex[2], hex[2]})
	}
	if len(hex) != 6 {
		return 0, false
	}
	r := float64(parseHexNibble(hex[0])<<4|parseHexNibble(hex[1])) / 255.0
	g := float64(parseHexNibble(hex[2])<<4|parseHexNibble(hex[3])) / 255.0
	b := float64(parseHexNibble(hex[4])<<4|parseHexNibble(hex[5])) / 255.0
	toLinear := func(c float64) float64 {
		if c <= 0.03928 {
			return c / 12.92
		}
		return math.Pow((c+0.055)/1.055, 2.4)
	}
	return 0.2126*toLinear(r) + 0.7152*toLinear(g) + 0.0722*toLinear(b), true
}

func wcagContrastRatio(l1, l2 float64) float64 {
	if l1 < l2 {
		l1, l2 = l2, l1
	}
	return (l1 + 0.05) / (l2 + 0.05)
}

func skipCheck(c *Check, reason string) {
	c.Skipped = true
	c.Passed = false
	c.Detail = reason
}

func setCheck(c *Check, passed bool, detailOK, detailFail string) {
	c.Passed = passed
	if passed {
		c.Detail = detailOK
	} else {
		c.Detail = detailFail
	}
}

func buildCategory(id, name string, checks []Check) Category {
	passed := 0
	total := 0
	for _, c := range checks {
		if c.Skipped {
			continue
		}
		total++
		if c.Passed {
			passed++
		}
	}
	return Category{
		ID:     id,
		Name:   name,
		Passed: passed,
		Total:  total,
		Checks: checks,
	}
}

func computeScore(categories []Category) int {
	deduction := 0
	for _, cat := range categories {
		for _, c := range cat.Checks {
			if !c.Passed && !c.Skipped {
				deduction += c.Impact
			}
		}
	}
	score := 100 - deduction
	if score < 0 {
		score = 0
	}
	return score
}

func computeGrade(score int, hasBlocker bool) string {
	var grade string
	switch {
	case score >= 95:
		grade = "A+"
	case score >= 88:
		grade = "A"
	case score >= 78:
		grade = "B"
	case score >= 65:
		grade = "C"
	case score >= 45:
		grade = "D"
	default:
		grade = "F"
	}
	if hasBlocker {
		switch grade {
		case "A+", "A", "B":
			grade = "C"
		}
	}
	return grade
}

func computeSummary(score int, categories []Category, loc locale) string {
	failedBlocker := 0
	failedWarning := 0
	for _, cat := range categories {
		for _, c := range cat.Checks {
			if c.Skipped {
				continue
			}
			if !c.Passed {
				switch c.Severity {
				case "blocker", "critical":
					failedBlocker++
				case "warning":
					failedWarning++
				}
			}
		}
	}

	switch {
	case failedBlocker > 0:
		return loc.tf("%d bloqueador(es) crítico(s) detectado(s). Este correo puede ser bloqueado o marcado como peligroso.",
			"%d critical blocker(s) detected. This email may be blocked or flagged as dangerous.", failedBlocker)
	case failedWarning > 2:
		return loc.tf("%d advertencias encontradas. Se recomienda revisar la estructura y compatibilidad.",
			"%d warnings found. Review of structure and compatibility is recommended.", failedWarning)
	case score >= 90:
		return loc.t("El correo está bien construido y cumple con las buenas prácticas de entregabilidad.",
			"The email is well-built and follows deliverability best practices.")
	case score >= 75:
		return loc.t("El correo es aceptable pero tiene oportunidades de mejora menores.",
			"The email is acceptable but has minor improvement opportunities.")
	default:
		return loc.t("El correo presenta varios problemas que pueden afectar su entregabilidad.",
			"The email has several issues that may affect its deliverability.")
	}
}

func firstHeader(headers map[string][]string, key string) string {
	if headers == nil {
		return ""
	}
	if vals, ok := headers[key]; ok && len(vals) > 0 {
		return vals[0]
	}
	return ""
}

func headerCount(headers map[string][]string, key string) int {
	if headers == nil {
		return 0
	}
	return len(headers[key])
}

func findDuplicateSingularHeaders(headers map[string][]string) []string {
	singular := []struct{ key, display string }{
		{"from", "From"},
		{"subject", "Subject"},
		{"date", "Date"},
		{"message-id", "Message-ID"},
		{"reply-to", "Reply-To"},
	}
	var duplicated []string
	for _, s := range singular {
		if headerCount(headers, s.key) > 1 {
			duplicated = append(duplicated, s.display)
		}
	}
	return duplicated
}

func extractFromDisplayName(from string) string {
	if idx := strings.Index(from, "<"); idx > 0 {
		name := strings.TrimSpace(from[:idx])
		return strings.Trim(name, `"'`)
	}
	return ""
}

func containsEmoji(s string) bool {
	for _, r := range s {
		switch {
		case r >= 0x1F300 && r <= 0x1FFFF:
			return true
		case r >= 0x2600 && r <= 0x27BF:
			return true
		case r >= 0xFE00 && r <= 0xFE0F:
			return true
		}
	}
	return false
}

func isAllCaps(s string) bool {
	letters := 0
	caps := 0
	for _, r := range s {
		if unicode.IsLetter(r) {
			letters++
			if unicode.IsUpper(r) {
				caps++
			}
		}
	}
	return letters > 3 && caps*100/letters > 70
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGT"[exp])
}

func checkVellumVerified(categories []Category) bool {
	for _, cat := range categories {
		for _, c := range cat.Checks {
			if c.Severity == "blocker" && !c.Passed && !c.Skipped {
				return false
			}
		}
	}
	return true
}

func vellumDisclaimer(verified bool, loc locale) string {
	if !verified {
		return ""
	}
	return loc.t(
		"Verificado en estructura y cabeceras RFC — sin bloqueadores críticos ni tácticas de engaño. La probabilidad de spam del contenido es una evaluación independiente realizada por Vellum Sentinel.",
		"Verified on structure and RFC headers — no critical blockers or deception tactics. Content spam probability is an independent assessment by Vellum Sentinel.",
	)
}
