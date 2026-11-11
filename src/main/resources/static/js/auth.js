(function () {
    "use strict";

    function togglePassword(button) {
        var controlId = button.getAttribute("aria-controls");
        var input = controlId ? document.getElementById(controlId) : null;
        if (!input) {
            return;
        }

        var showing = input.type === "text";
        input.type = showing ? "password" : "text";
        button.setAttribute("aria-label", showing ? "Show password" : "Hide password");
    }

    function setMode(mode) {
        var shell = document.querySelector(".auth-shell[data-auth-mode]");
        if (!shell || (mode !== "login" && mode !== "register")) {
            return;
        }

        shell.setAttribute("data-auth-mode", mode);
        var heading = shell.querySelector('[data-auth-panel="' + mode + '"] h2');
        if (heading) {
            heading.focus({ preventScroll: true });
        }
    }

    document.addEventListener("click", function (event) {
        var toggle = event.target.closest("[data-password-toggle]");
        if (toggle) {
            togglePassword(toggle);
            return;
        }

        var modeLink = event.target.closest("[data-auth-mode-target]");
        if (modeLink) {
            event.preventDefault();
            setMode(modeLink.getAttribute("data-auth-mode-target"));
        }
    });

    document.addEventListener("submit", function (event) {
        var form = event.target.closest("[data-auth-form]");
        if (!form) {
            return;
        }

        var button = form.querySelector("[data-submit-button]");
        if (button) {
            button.disabled = true;
            button.setAttribute("aria-disabled", "true");
        }
        form.classList.add("is-submitting");
    });

    if (window.location.hash === "#register") {
        setMode("register");
    }
})();
