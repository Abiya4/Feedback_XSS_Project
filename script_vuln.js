console.log("JS file loaded!");
document.addEventListener('DOMContentLoaded', () => {
    const submitBtn = document.getElementById('vuln-submit-btn');

    if (submitBtn) {
        submitBtn.addEventListener('click', (e) => {
            e.preventDefault();

            // Capture raw input for student info
            const studentName = document.getElementById('vuln-student-name').value;
            const studentRoll = document.getElementById('vuln-student-roll').value;

            // Capture raw input for modules 1-6 feedback
            const feedbackMod1 = document.getElementById('vuln-feedback-mod1').value;
            const feedbackMod2 = document.getElementById('vuln-feedback-mod2').value;
            const feedbackMod3 = document.getElementById('vuln-feedback-mod3').value;
            const feedbackMod4 = document.getElementById('vuln-feedback-mod4').value;
            const feedbackMod5 = document.getElementById('vuln-feedback-mod5').value;
            const feedbackMod6 = document.getElementById('vuln-feedback-mod6').value;

            // Capture raw input for teacher feedback
            const feedbackTeacher = document.getElementById('vuln-feedback-teacher').value;

            // Capture selected radio button values for each module and teacher
            const getRating = (name) => {
                const checked = document.querySelector(`input[name="${name}"]:checked`);
                return checked ? checked.value : null;
            };

            const ratingMod1 = getRating('vuln-mod1-rating');
            const ratingMod2 = getRating('vuln-mod2-rating');
            const ratingMod3 = getRating('vuln-mod3-rating');
            const ratingMod4 = getRating('vuln-mod4-rating');
            const ratingMod5 = getRating('vuln-mod5-rating');
            const ratingMod6 = getRating('vuln-mod6-rating');
            const ratingTeacher = getRating('vuln-teacher-rating');

            // Handle Output / Preview Area
            // Person 3 & 4 will implement actual display logic here
            const outputContent = document.getElementById('vuln-output-content');
            
            // Console log for testing if needed
            console.log("Captured Vulnerable Data:", {
                studentName, studentRoll,
                feedbackMod1, ratingMod1,
                feedbackMod2, ratingMod2,
                feedbackMod3, ratingMod3,
                feedbackMod4, ratingMod4,
                feedbackMod5, ratingMod5,
                feedbackMod6, ratingMod6,
                feedbackTeacher, ratingTeacher
            });
        });
    }
});
