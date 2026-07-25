// Closes any open <details class="profile-menu"> when the user clicks
// outside it. Native <details>/<summary> gives us a fully keyboard- and
// screen-reader-accessible dropdown for free (no ARIA wiring needed), but
// it doesn't close on outside-click by itself - this is the one bit of
// behavior vanilla HTML doesn't cover, so it's the one bit of JS this app
// ships. Loaded as an external file (not inline) to stay compatible with
// the site's Content-Security-Policy, which disallows inline scripts.
document.addEventListener('click', (event) => {
  document.querySelectorAll('details.profile-menu[open]').forEach((menu) => {
    if (!menu.contains(event.target)) {
      menu.removeAttribute('open');
    }
  });
});

// Also close on Escape, for keyboard users.
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') {
    document.querySelectorAll('details.profile-menu[open]').forEach((menu) => {
      menu.removeAttribute('open');
    });
  }
});