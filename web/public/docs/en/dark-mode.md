# Dark mode in emails {#top}

Email clients have two distinct behaviors toward dark mode: some respect the CSS you wrote, and others ignore it entirely and invert colors on their own. These are two different problems and require different solutions.

## Standard dark mode {#standard-dark-mode}

Standard dark mode works through a CSS media query and, optionally, a color scheme meta tag. Clients that support it apply the styles you define when the recipient's operating system is in dark mode.

Clients that respect this mode: **Apple Mail**, **Thunderbird**, and some recent versions of **Outlook for Mac**.

For it to work, the email's HTML needs to explicitly declare support:

```html
<meta name="color-scheme" content="light dark">
```

```css
@media (prefers-color-scheme: dark) {
  body {
    background-color: #1a1a1a;
    color: #e5e5e5;
  }
  /* rest of overrides */
}
```

The meta tag tells the client that the email is prepared for both color schemes. Without it, some clients may not activate the media query even if the system is in dark mode. The media query defines exactly how elements should look when dark mode is active.

If the email has neither of these declarations, the client applies its own default behavior, which in most cases results in an uncontrolled color inversion.

## Forced dark mode {#forced-dark-mode}

Forced dark mode is different: the client completely ignores the email's CSS and applies its own color inversion algorithm. It does not matter if you have a well-written media query. The client converts light backgrounds to dark and dark colors to light using its own logic.

Clients that do this: **Gmail for Android and iOS** and **Outlook for Windows**.

The result can be unpredictable:

- White backgrounds become dark gray or black.
- Text that was dark becomes light, but with unexpected color tints.
- PNG images with transparent backgrounds containing dark icons or logos become completely invisible, because the black icon on a transparent background is now on a black background.
- Gradients and borders can end up with unexpected colors.

To mitigate the effects of forced dark mode without breaking the design in light mode:

- Add a subtle white border or glow to logos and icons that use transparent PNG.
- Avoid relying on text inheriting the correct color; define explicit colors with inline `color` where contrast is critical.
- Test the email with the **forced dark** option in Vellum's preview, which simulates the Gmail and Outlook algorithm before sending.

## Preventing automatic color inversion (opt-out) {#opt-out-dark-mode}

Some email clients support the CSS `color-scheme` property with the value `only light`. When present, these clients are instructed **not** to apply any automatic dark mode transformation to the email. The original colors and design are preserved exactly as written.

Clients that respect this opt-out: **Samsung Mail**, some builds of **Outlook for Windows**, and **Yahoo Mail** in certain environments.

To apply the opt-out, declare the property in the `<style>` block and optionally inline on the `<body>`:

```html
<style>
  :root { color-scheme: only light; }
</style>
```

Or inline on the body element:

```html
<body style="color-scheme: only light;">
```

> **Important:** this declaration does not affect clients that support the standard `prefers-color-scheme` media query (Apple Mail, Thunderbird, Outlook for Mac). Those clients will still activate your own dark mode styles if you have written a media query. The opt-out only prevents clients that would otherwise apply a forced automatic inversion.

### Recommended combined strategy

For the most robust result across all major clients, use all three declarations together:

```html
<!-- 1. Tell clients the email is designed only for light mode -->
<meta name="color-scheme" content="light">

<style>
  /* 2. Opt out of forced automatic inversion on supporting clients */
  :root { color-scheme: only light; }

  /* 3. Optional: explicit dark mode styles for clients that respect media queries */
  @media (prefers-color-scheme: dark) {
    body { background-color: #ffffff; color: #1a1a1a; }
  }
</style>
```

This approach covers:
- **Gmail / Outlook for Windows** — forced inversion is suppressed via `color-scheme: only light`
- **Apple Mail / Thunderbird** — your own dark mode overrides take effect via the media query
- **Other clients** — the `<meta>` tag signals light-only design preference

## Why one alone is not enough {#why-both}

Writing only the standard media query does not protect the email in the Gmail app or Outlook for Windows, because those clients do not read it. But ignoring the media query and trusting that all clients will force the colors does not work either, because Apple Mail and Thunderbird do respect the CSS and the email would be left without its own dark mode styles.

The most robust approach is to declare support in the color scheme meta tag, write the overrides in the media query for standard clients, add the `color-scheme: only light` opt-out to suppress forced inversions, and verify the result with the forced dark mode simulation to make sure images and critical colors withstand the automatic inversion.
