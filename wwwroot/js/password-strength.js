// Simple client-side password strength evaluation matching the server rules
(function () {
    function scorePassword(pwd) {
        var score = 0;
        if (!pwd) return { score: 0, desc: 'Very weak' };
        if (pwd.length >= 12) score++;
        if (/[a-z]/.test(pwd)) score++;
        if (/[A-Z]/.test(pwd)) score++;
        if (/\d/.test(pwd)) score++;
        if (/[^A-Za-z0-9]/.test(pwd)) score++;
        var desc = ['Very weak', 'Weak', 'Medium', 'Strong', 'Very strong', 'Excellent'][score];
        return { score: score, desc: desc };
    }

    window.passwordStrength = {
        evaluate: scorePassword
    };
})();
