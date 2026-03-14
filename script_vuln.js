// ============================================================
//  script_vuln.js  —  VULNERABLE VERSION
//  SIC Macro Project 12: XSS Attack & Defense Demo
//
//  ⚠️  INTENTIONALLY VULNERABLE — FOR EDUCATIONAL PURPOSES ONLY
//
//  This script directly injects user-supplied input into the DOM
//  using innerHTML WITHOUT any sanitization. This deliberately
//  allows Reflected Cross-Site Scripting (XSS) attacks.
//
//  Demo payload: <script>alert("XSS Attack")</script>
//  or:           <img src=x onerror="alert('XSS!')">
//
//  Person 3 Implementation: Display logic + XSS demonstration
// ============================================================

console.log("script_vuln.js loaded — ⚠️ Vulnerable Version Active");

document.addEventListener('DOMContentLoaded', () => {

    // ── Element References ──────────────────────────────────
    const submitBtn  = document.getElementById('vuln-submit-btn');
    const resetBtn   = document.getElementById('vuln-reset-btn');
    const outputArea = document.getElementById('vuln-output-area');
    const outputContent = document.getElementById('vuln-output-content');
    const toast      = document.getElementById('vuln-toast');

    // ── Helper: Get selected star rating value ──────────────
    // Returns the numeric value (1–5) of the checked radio button,
    // or 'Not Rated' if the student did not select a rating.
    const getRating = (name) => {
        const checked = document.querySelector(`input[name="${name}"]:checked`);
        return checked ? checked.value : null;
    };

    // ── Helper: Build star string from numeric rating ───────
    // Converts a numeric value (e.g. "4") into a filled/empty
    // star string like "★★★★☆" for display in the output panel.
    const buildStars = (value) => {
        if (!value) return '<span style="color:#64748b;">Not Rated</span>';
        const filled = parseInt(value);
        return '★'.repeat(filled) + '☆'.repeat(5 - filled);
    };

    // ── Helper: Show toast notification ────────────────────
    const showToast = (message, type = 'success') => {
        toast.textContent = message;
        toast.className = `toast ${type} show`;
        setTimeout(() => {
            toast.classList.remove('show');
        }, 3000);
    };

    // ── Submit Button: Main Event Listener ─────────────────
    if (submitBtn) {
        submitBtn.addEventListener('click', (e) => {
            e.preventDefault();

            // ── Step 1: Capture raw input values ────────────
            // NO sanitization is applied — values are taken
            // directly from .value and injected via innerHTML.
            const studentName = document.getElementById('vuln-student-name').value;
            const studentRoll = document.getElementById('vuln-student-roll').value;

            // Module feedback text (raw, unsanitized)
            const feedbackMod1 = document.getElementById('vuln-feedback-mod1').value;
            const feedbackMod2 = document.getElementById('vuln-feedback-mod2').value;
            const feedbackMod3 = document.getElementById('vuln-feedback-mod3').value;
            const feedbackMod4 = document.getElementById('vuln-feedback-mod4').value;
            const feedbackMod5 = document.getElementById('vuln-feedback-mod5').value;
            const feedbackMod6 = document.getElementById('vuln-feedback-mod6').value;

            // Teacher feedback text (raw, unsanitized)
            const feedbackTeacher = document.getElementById('vuln-feedback-teacher').value;

            // ── Step 2: Capture star rating values ──────────
            const ratingMod1    = getRating('vuln-mod1-rating');
            const ratingMod2    = getRating('vuln-mod2-rating');
            const ratingMod3    = getRating('vuln-mod3-rating');
            const ratingMod4    = getRating('vuln-mod4-rating');
            const ratingMod5    = getRating('vuln-mod5-rating');
            const ratingMod6    = getRating('vuln-mod6-rating');
            const ratingTeacher = getRating('vuln-teacher-rating');

            // ── Step 3: Validation — ensure name is filled ──
            if (!studentName.trim()) {
                showToast('⚠️ Please enter your name before submitting.', 'warning');
                return;
            }

            // ── Step 4: Console log for debugging ───────────
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

            // ── Step 5: Build output HTML ────────────────────
            //
            // ⚠️  VULNERABILITY: All user values are embedded
            // directly into the HTML string without escaping.
            // Any <script> tags or event-handler attributes in
            // the input will be parsed and executed by the browser
            // when this string is assigned to innerHTML below.
            //
            // Example attack payload (try in the feedback box):
            //   <script>alert("XSS Attack")</script>
            //   <img src=x onerror="alert('XSS via img tag!')">
            //   <svg onload="alert('SVG XSS')">
            //
            const outputHTML = `
                <!-- ⚠️ XSS VULNERABILITY: innerHTML used without sanitization -->

                <!-- Student Info -->
                <div style="margin-bottom:20px; padding-bottom:16px; border-bottom:1px solid #334155;">
                    <p style="font-size:0.75rem; text-transform:uppercase; letter-spacing:0.06em; color:#64748b; margin-bottom:4px;">Student</p>
                    <p style="font-size:1.1rem; font-weight:700; color:#f1f5f9;">${studentName}</p>
                    ${studentRoll ? `<p style="font-size:0.85rem; color:#94a3b8; margin-top:2px;">Roll No: ${studentRoll}</p>` : ''}
                </div>

                <!-- XSS Warning Banner -->
                <div style="background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.3); border-radius:8px; padding:10px 14px; margin-bottom:20px; font-size:0.78rem; color:#fca5a5;">
                    ⚠️ <strong>Vulnerable Version:</strong> Input is rendered via <code>innerHTML</code> without sanitization. Malicious scripts in feedback fields will execute.
                </div>

                <!-- Module Ratings -->
                <p style="font-size:0.78rem; text-transform:uppercase; letter-spacing:0.06em; color:#64748b; margin-bottom:12px;">Module Ratings &amp; Feedback</p>

                <div style="display:flex; flex-direction:column; gap:12px; margin-bottom:20px;">

                    <!-- Module 1 -->
                    <div style="background:#0f172a; border-radius:8px; padding:14px 18px;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                            <span style="font-size:0.8rem; font-weight:700; color:#818cf8;">Module 1 — Basics of Number Theory and Security</span>
                            <span style="color:#facc15; font-size:1rem;">${buildStars(ratingMod1)}</span>
                        </div>
                        <div style="font-size:0.88rem; color:#94a3b8;">${feedbackMod1 || '<em style="color:#475569;">No feedback provided.</em>'}</div>
                    </div>

                    <!-- Module 2 -->
                    <div style="background:#0f172a; border-radius:8px; padding:14px 18px;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                            <span style="font-size:0.8rem; font-weight:700; color:#818cf8;">Module 2 — Symmetric Ciphers</span>
                            <span style="color:#facc15; font-size:1rem;">${buildStars(ratingMod2)}</span>
                        </div>
                        <div style="font-size:0.88rem; color:#94a3b8;">${feedbackMod2 || '<em style="color:#475569;">No feedback provided.</em>'}</div>
                    </div>

                    <!-- Module 3 -->
                    <div style="background:#0f172a; border-radius:8px; padding:14px 18px;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                            <span style="font-size:0.8rem; font-weight:700; color:#818cf8;">Module 3 — Asymmetric Ciphers and Key Distribution</span>
                            <span style="color:#facc15; font-size:1rem;">${buildStars(ratingMod3)}</span>
                        </div>
                        <div style="font-size:0.88rem; color:#94a3b8;">${feedbackMod3 || '<em style="color:#475569;">No feedback provided.</em>'}</div>
                    </div>

                    <!-- Module 4 -->
                    <div style="background:#0f172a; border-radius:8px; padding:14px 18px;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                            <span style="font-size:0.8rem; font-weight:700; color:#818cf8;">Module 4 — Cryptographic Data Integrity Concepts</span>
                            <span style="color:#facc15; font-size:1rem;">${buildStars(ratingMod4)}</span>
                        </div>
                        <div style="font-size:0.88rem; color:#94a3b8;">${feedbackMod4 || '<em style="color:#475569;">No feedback provided.</em>'}</div>
                    </div>

                    <!-- Module 5 -->
                    <div style="background:#0f172a; border-radius:8px; padding:14px 18px;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                            <span style="font-size:0.8rem; font-weight:700; color:#818cf8;">Module 5 — Network and Internet Security</span>
                            <span style="color:#facc15; font-size:1rem;">${buildStars(ratingMod5)}</span>
                        </div>
                        <div style="font-size:0.88rem; color:#94a3b8;">${feedbackMod5 || '<em style="color:#475569;">No feedback provided.</em>'}</div>
                    </div>

                    <!-- Module 6 -->
                    <div style="background:#0f172a; border-radius:8px; padding:14px 18px;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                            <span style="font-size:0.8rem; font-weight:700; color:#818cf8;">Module 6 — Cloud and IoT Security</span>
                            <span style="color:#facc15; font-size:1rem;">${buildStars(ratingMod6)}</span>
                        </div>
                        <div style="font-size:0.88rem; color:#94a3b8;">${feedbackMod6 || '<em style="color:#475569;">No feedback provided.</em>'}</div>
                    </div>

                </div>

                <!-- Teacher Rating -->
                <p style="font-size:0.78rem; text-transform:uppercase; letter-spacing:0.06em; color:#64748b; margin-bottom:12px;">Teacher Rating &amp; Feedback</p>
                <div style="background:#0f172a; border-radius:8px; padding:14px 18px; border-left:3px solid #a78bfa;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                        <span style="font-size:0.8rem; font-weight:700; color:#c4b5fd;">Ms. Anita John</span>
                        <span style="color:#facc15; font-size:1rem;">${buildStars(ratingTeacher)}</span>
                    </div>
                    <div style="font-size:0.88rem; color:#94a3b8;">${feedbackTeacher || '<em style="color:#475569;">No feedback provided.</em>'}</div>
                </div>
            `;

            // ── Step 6: ⚠️ VULNERABLE innerHTML Injection ───
            // This is the primary XSS sink. User input is written directly
            // into the DOM as raw HTML — NO escaping, NO sanitization.
            outputContent.innerHTML = outputHTML;

            // ── ⚠️ BYPASS HTML5 SCRIPT EXECUTION BLOCK ───
            // Modern browsers block <script> tags inserted via innerHTML
            // as a default security measure. Since this is an intentional
            // demo and we specifically want <script> payloads to work,
            // we manually find and evaluate any injected <script> tags.
            Array.from(outputContent.querySelectorAll('script')).forEach(oldScript => {
                const newScript = document.createElement('script');
                Array.from(oldScript.attributes).forEach(attr => newScript.setAttribute(attr.name, attr.value));
                newScript.appendChild(document.createTextNode(oldScript.innerHTML));
                oldScript.parentNode.replaceChild(newScript, oldScript);
            });

            // ── Step 7: Show the output area ────────────────
            outputArea.style.display = 'block';
            outputArea.scrollIntoView({ behavior: 'smooth', block: 'start' });

            // ── Step 8: Show success toast ───────────────────
            showToast('✅ Feedback submitted! (Unsanitized)', 'success');
        });
    }

    // ── Reset Button ────────────────────────────────────────
    // Clears all form fields and hides the output panel.
    if (resetBtn) {
        resetBtn.addEventListener('click', () => {
            // Clear text inputs
            document.getElementById('vuln-student-name').value = '';
            document.getElementById('vuln-student-roll').value = '';

            // Clear all textareas
            ['mod1','mod2','mod3','mod4','mod5','mod6','teacher'].forEach(key => {
                const ta = document.getElementById(`vuln-feedback-${key}`);
                if (ta) ta.value = '';
            });

            // Uncheck all radio buttons
            document.querySelectorAll('input[type="radio"]').forEach(r => {
                r.checked = false;
            });

            // Hide and clear output panel
            outputArea.style.display  = 'none';
            outputContent.innerHTML   = '';

            showToast('🔄 Form reset.', 'warning');
        });
    }

});
