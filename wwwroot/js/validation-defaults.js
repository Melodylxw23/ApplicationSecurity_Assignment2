// Ensure jquery-validation escapes HTML in messages to avoid inserting untrusted HTML
(function () {
    function applyDefaults() {
        if (window.jQuery && jQuery.validator && typeof jQuery.validator.setDefaults === 'function') {
            try {
                jQuery.validator.setDefaults({ escapeHtml: true });
            } catch (e) {
                // ignore
            }
            return true;
        }
        return false;
    }

    if (!applyDefaults()) {
        // try again once DOM is ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', function () { applyDefaults(); });
        } else {
            setTimeout(applyDefaults, 100);
        }
    }
})();
