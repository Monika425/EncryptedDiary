function togglePassword(id, button) {

    const input = document.getElementById(id);

    if (input.type === "password") {

        input.type = "text";

        button.innerText = "Hide";

    } else {

        input.type = "password";

        button.innerText = "Show";
    }
}