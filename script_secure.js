// ============================================================
//  script_secure.js  —  SECURE VERSION
//  SIC Macro Project 12: XSS Attack & Defense Demo
//
//  ✅  INTENTIONALLY SECURE — XSS DEFENSE DEMONSTRATION
//
//  This script applies multiple layers of defense against
//  Cross-Site Scripting (XSS) attacks:
//
//  DEFENSE LAYER 1 — Input Validation
//    Checks that user input meets expected rules before
//    processing. Example: name must not contain HTML tags.
//
//  DEFENSE LAYER 2 — Input Sanitization
//    Strips or neutralizes dangerous content from raw input
//    before it is used anywhere in the page.
//
//  DEFENSE LAYER 3 — Output Encoding (HTML Escaping)
//    Converts special HTML characters like < > & " ' into
//    their safe HTML entity equivalents (&lt; &gt; &amp; etc.)
//    so the browser treats them as plain text, NOT as code.
//
//  DEFENSE LAYER 4 — Safe DOM Insertion (textContent)
//    Uses textContent / createElement instead of innerHTML
//    so user data is NEVER parsed as HTML by the browser.
//
//  WHY THESE DEFENSES WORK:
//    The vulnerable version uses:
//      outputContent.innerHTML = `...${userInput}...`
//    This lets the browser PARSE and EXECUTE HTML/JS in userInput.
//
//    The secure version uses:
//      element.textContent = userInput
//    textContent tells the browser: "this is plain text only."
//    Even if the user types <script>alert(1)</script>,
//    the browser will DISPLAY those characters — not run them.
//
//  Person 4 Implementation: XSS Defense — Validation & Sanitization
// ============================================================

console.log("script_secure.js loaded — ✅ Secure Version Active");

document.addEventListener('DOMContentLoaded', () => {

    // ── Element References ──────────────────────────────────
    // We grab references to all the DOM elements we need.
    // This is standard setup — same as the vulnerable version.
    const submitBtn     = document.getElementById('sec-submit-btn');
    const resetBtn      = document.getElementById('sec-reset-btn');
    const outputArea    = document.getElementById('sec-output-area');
    const outputContent = document.getElementById('sec-output-content');
    const toast         = document.getElementById('sec-toast');


    // ════════════════════════════════════════════════════════
    // DEFENSE LAYER 3 — OUTPUT ENCODING / HTML ESCAPING
    // ════════════════════════════════════════════════════════
    //
    // CONCEPT: HTML Escaping
    // ─────────────────────
    // HTML has "special characters" that the browser interprets
    // as code structure, not as text. These are:
    //
    //   Character  |  Meaning in HTML          |  Safe Entity
    //   -----------|---------------------------|-------------
    //      &        |  Start of HTML entity     |  &amp;
    //      <        |  Start of HTML tag        |  &lt;
    //      >        |  End of HTML tag          |  &gt;
    //      "        |  Attribute value quotes   |  &quot;
    //      '        |  Attribute value quotes   |  &#x27;
    //      /        |  Closing tag slash        |  &#x2F;
    //
    // If a user types:  <script>alert("XSS")</script>
    // After escaping:   &lt;script&gt;alert(&quot;XSS&quot;)&lt;&#x2F;script&gt;
    //
    // The browser sees this as TEXT — not a script tag.
    // So it renders:    <script>alert("XSS")</script>  (as visible text)
    // And does NOT execute the alert.
    //
    // This function is the CORE of XSS output defense.
    // It must be applied to EVERY piece of user input before
    // embedding it into HTML strings.
    //
    // NOTE: We handle & FIRST — if we handled < first, then
    // converted & to &amp; later, we'd corrupt the already-
    // converted entities like &lt; → &amp;lt;
    //
    const escapeHTML = (str) => {
        // Step 0: Convert to string — protects against non-string inputs
        // (e.g., numbers, null, undefined passed accidentally)
        if (str === null || str === undefined) return '';
        str = String(str);

        // Step 1: Escape & first (MUST be first — see note above)
        // Without this, a later pass on < would turn &lt; into &amp;lt;
        return str
            .replace(/&/g,  '&amp;')   // & → &amp;
            .replace(/</g,  '&lt;')    // < → &lt;   (blocks <script>, <img>, etc.)
            .replace(/>/g,  '&gt;')    // > → &gt;   (blocks closing tags)
            .replace(/"/g,  '&quot;')  // " → &quot; (blocks attribute injection)
            .replace(/'/g,  '&#x27;')  // ' → &#x27; (blocks single-quote injection)
            .replace(/\//g, '&#x2F;'); // / → &#x2F; (blocks </script> style closings)
    };
    // ── End of escapeHTML ────────────────────────────────────


    // ════════════════════════════════════════════════════════
    // DEFENSE LAYER 2 — INPUT SANITIZATION
    // ════════════════════════════════════════════════════════
    //
    // CONCEPT: Sanitization vs Escaping
    // ──────────────────────────────────
    // Escaping (above) makes dangerous characters "safe to display."
    // Sanitization actually REMOVES or STRIPS the dangerous parts.
    //
    // Think of it like this:
    //   Escaping  = "Defang the snake — keep it, but remove its fangs"
    //   Sanitization = "Remove the snake entirely"
    //
    // For feedback text, we don't want HTML at all.
    // So we strip all HTML tags completely using a regex.
    //
    // REGEX EXPLANATION:
    //   /<[^>]*>/g
    //   <       → literal opening angle bracket
    //   [^>]*   → any characters that are NOT > (the tag content)
    //   >       → literal closing angle bracket
    //   /g      → global flag — replace ALL occurrences, not just first
    //
    // Examples:
    //   Input:  <script>alert(1)</script>
    //   Output: alert(1)        ← tags stripped, text content kept
    //
    //   Input:  <img src=x onerror="alert('XSS')">
    //   Output: (empty string)  ← entire self-closing tag removed
    //
    // Note: Sanitization alone is NOT enough — we still escape
    // after sanitizing as a second layer of protection.
    //
    const sanitizeInput = (str) => {
        if (str === null || str === undefined) return '';
        str = String(str);

        // Strip all HTML tags
        str = str.replace(/<[^>]*>/g, '');

        // Also strip dangerous JavaScript pseudo-protocols
        // These are used in href/src attributes to run JS:
        //   href="javascript:alert(1)"
        //   src="data:text/html,<script>alert(1)</script>"
        //
        // REGEX: /javascript\s*:/gi
        //   javascript  → literal text
        //   \s*         → zero or more whitespace (attackers sometimes insert spaces)
        //   :           → the colon that follows
        //   /gi         → case-insensitive, global
        str = str.replace(/javascript\s*:/gi, '');

        // Strip data: URIs (used for Base64-encoded XSS payloads)
        str = str.replace(/data\s*:/gi, '');

        // Strip vbscript: (old IE attack vector)
        str = str.replace(/vbscript\s*:/gi, '');

        // Strip event handler attributes (onclick, onerror, onload, etc.)
        // These can appear even after tag stripping if they're inline
        //
        // REGEX: /on\w+\s*=\s*["'][^"']*["']/gi
        //   on     → starts with "on" (all HTML event handlers)
        //   \w+    → one or more word characters (click, error, load, etc.)
        //   \s*=\s*→ equals sign with optional spaces
        //   ["']   → opening quote
        //   [^"']* → anything except the closing quote
        //   ["']   → closing quote
        str = str.replace(/on\w+\s*=\s*["'][^"']*["']/gi, '');

        // Trim leading/trailing whitespace for clean display
        return str.trim();
    };
    // ── End of sanitizeInput ─────────────────────────────────


    // ════════════════════════════════════════════════════════
    // DEFENSE LAYER 1 — INPUT VALIDATION
    // ════════════════════════════════════════════════════════
    //
    // CONCEPT: Input Validation
    // ─────────────────────────
    // Validation checks whether the input MAKES SENSE and
    // meets the rules we define BEFORE we process it.
    //
    // This is the FIRST line of defense — we reject bad input
    // before it even enters the system.
    //
    // For this form:
    //   - Name is required (can't be empty)
    //   - Name should not contain HTML angle brackets
    //     (a legitimate name never has < or > in it)
    //   - Name should not be suspiciously long (max 100 chars)
    //
    // Note: Validation does NOT replace sanitization or escaping.
    // Attackers can sometimes bypass validation. Always apply
    // all layers.
    //
    const validateName = (name) => {
        // Rule 1: Must not be empty
        if (!name || name.trim() === '') {
            return { valid: false, message: '⚠️ Please enter your name before submitting.' };
        }

        // Rule 2: Must not exceed reasonable length
        // (prevents buffer overflow-style attacks or UI breakage)
        if (name.trim().length > 100) {
            return { valid: false, message: '⚠️ Name must not exceed 100 characters.' };
        }

        // Rule 3: Name should not contain angle brackets
        // A legitimate name (e.g., "Abiya John") never has < or >
        // If it does, it's almost certainly an injection attempt.
        if (/<|>/.test(name)) {
            return { valid: false, message: '🚨 Invalid input: Name contains illegal characters.' };
        }

        // Rule 4: Name should not contain script-related keywords
        // (extra caution — belt AND suspenders approach)
        const dangerousPatterns = /script|onerror|onload|onclick|javascript|alert/i;
        if (dangerousPatterns.test(name)) {
            return { valid: false, message: '🚨 Suspicious input detected in name field.' };
        }

        return { valid: true, message: '' };
    };
    // ── End of validateName ──────────────────────────────────


    // ════════════════════════════════════════════════════════
    // HELPER: Get selected star rating value
    // ════════════════════════════════════════════════════════
    //
    // This reads the currently selected radio button for a
    // given rating group name. Returns the numeric value (1–5)
    // or null if no rating was selected.
    //
    // Safe note: Radio values are controlled by us (hardcoded
    // in HTML as 1–5), so no escaping is needed for rating values.
    //
    const getRating = (name) => {
        const checked = document.querySelector(`input[name="${name}"]:checked`);
        return checked ? checked.value : null;
    };


    // ════════════════════════════════════════════════════════
    // HELPER: Build star display string
    // ════════════════════════════════════════════════════════
    //
    // Converts numeric rating (e.g., "4") into a visual star
    // string like "★★★★☆".
    //
    // SECURITY NOTE: The output of this function is a plain
    // Unicode string (★ and ☆ characters). These are NOT HTML.
    // They will be inserted safely using textContent — not innerHTML.
    // So no escaping is needed here.
    //
    const buildStars = (value) => {
        if (!value) return 'Not Rated';
        const filled = parseInt(value);
        if (isNaN(filled) || filled < 1 || filled > 5) return 'Not Rated';
        return '★'.repeat(filled) + '☆'.repeat(5 - filled);
    };


    // ════════════════════════════════════════════════════════
    // HELPER: Show toast notification
    // ════════════════════════════════════════════════════════
    //
    // Displays a brief notification at the bottom-right corner.
    // 'type' can be 'success', 'error', or 'warning' — these
    // map to CSS classes defined in style.css.
    //
    const showToast = (message, type = 'success') => {
        toast.textContent = message; // ✅ textContent — safe
        toast.className = `toast ${type} show`;
        setTimeout(() => {
            toast.classList.remove('show');
        }, 3000);
    };


    // ════════════════════════════════════════════════════════
    // DEFENSE LAYER 4 — SAFE DOM BUILDING WITH createElement
    // ════════════════════════════════════════════════════════
    //
    // CONCEPT: Why createElement + textContent is Safe
    // ─────────────────────────────────────────────────
    // The vulnerable version builds a giant HTML string and
    // assigns it to innerHTML. This causes the browser to PARSE
    // the string as HTML — running any embedded scripts.
    //
    // The secure approach:
    //   1. Create DOM elements with document.createElement()
    //   2. Set their content using element.textContent = value
    //
    // When you use textContent, the browser treats the value
    // as PLAIN TEXT only. HTML tags are NOT parsed.
    //
    // Example:
    //   element.innerHTML = '<b>hello</b>'
    //   → Browser renders: hello (bold)  ← parses as HTML
    //
    //   element.textContent = '<b>hello</b>'
    //   → Browser renders: <b>hello</b>  ← treats as plain text
    //
    // This function builds a single module feedback card safely.
    //
    // Parameters:
    //   moduleName  — e.g., "Module 1 — Basics of Number Theory"
    //   rating      — raw value from radio button (e.g., "4")
    //   feedback    — raw user text from textarea
    //
    const buildModuleCard = (moduleName, rating, feedback) => {

        // ── Sanitize + Escape all user data ─────────────────
        // Even though we use textContent (which is already safe),
        // we sanitize as a bonus layer — defense in depth.
        // If any code path accidentally uses innerHTML later,
        // the data is already cleaned.
        const safeFeedback = escapeHTML(sanitizeInput(feedback));

        // Rating comes from our own HTML radio buttons (values 1–5)
        // so it's trusted, but we still validate it's a number.
        const safeStars = buildStars(rating);

        // ── Build card container ─────────────────────────────
        const card = document.createElement('div');
        card.style.cssText = `
            background: #0f172a;
            border-radius: 8px;
            padding: 14px 18px;
            margin-bottom: 12px;
        `;

        // ── Module name row ──────────────────────────────────
        const headerRow = document.createElement('div');
        headerRow.style.cssText = `
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 6px;
        `;

        // ✅ SAFE: textContent does NOT parse HTML
        const nameSpan = document.createElement('span');
        nameSpan.style.cssText = 'font-size:0.8rem; font-weight:700; color:#818cf8;';
        nameSpan.textContent = moduleName; // ← textContent: safe

        const starsSpan = document.createElement('span');
        starsSpan.style.cssText = 'color:#facc15; font-size:1rem;';
        starsSpan.textContent = safeStars; // ← textContent: safe

        headerRow.appendChild(nameSpan);
        headerRow.appendChild(starsSpan);

        // ── Feedback text ────────────────────────────────────
        const feedbackDiv = document.createElement('div');
        feedbackDiv.style.cssText = 'font-size:0.88rem; color:#94a3b8;';

        if (feedback && feedback.trim()) {
            // ✅ SAFE: textContent — even if safeFeedback contained
            // escaped entities like &lt;script&gt;, textContent
            // will display them as literal characters, not HTML.
            // We use the sanitized version for clean display.
            feedbackDiv.textContent = sanitizeInput(feedback);
        } else {
            feedbackDiv.style.cssText += ' color:#475569; font-style:italic;';
            feedbackDiv.textContent = 'No feedback provided.'; // static string, safe
        }

        // ── Assemble card ────────────────────────────────────
        card.appendChild(headerRow);
        card.appendChild(feedbackDiv);

        return card; // returns a DOM node, not an HTML string
    };
    // ── End of buildModuleCard ───────────────────────────────


    // ════════════════════════════════════════════════════════
    // SUBMIT BUTTON — MAIN EVENT LISTENER
    // ════════════════════════════════════════════════════════
    if (submitBtn) {
        submitBtn.addEventListener('click', (e) => {
            e.preventDefault();


            // ── STEP 1: Capture raw input values ────────────
            // We read raw .value from all fields.
            // At this point, NO sanitization has happened yet.
            // The raw values are only used for validation first.
            const rawName    = document.getElementById('sec-student-name').value;
            const rawRoll    = document.getElementById('sec-student-roll').value;

            const rawMod1    = document.getElementById('sec-feedback-mod1').value;
            const rawMod2    = document.getElementById('sec-feedback-mod2').value;
            const rawMod3    = document.getElementById('sec-feedback-mod3').value;
            const rawMod4    = document.getElementById('sec-feedback-mod4').value;
            const rawMod5    = document.getElementById('sec-feedback-mod5').value;
            const rawMod6    = document.getElementById('sec-feedback-mod6').value;
            const rawTeacher = document.getElementById('sec-feedback-teacher').value;


            // ── STEP 2: DEFENSE LAYER 1 — Validate name ─────
            //
            // We run validation on the raw name BEFORE any
            // processing. If validation fails, we stop here
            // and show an error — no further processing occurs.
            //
            const validation = validateName(rawName);
            if (!validation.valid) {
                showToast(validation.message, 'warning');
                return; // ← STOP. Do not process bad input.
            }


            // ── STEP 3: DEFENSE LAYER 2 — Sanitize inputs ───
            //
            // Now we sanitize ALL inputs. This strips HTML tags
            // and dangerous patterns from every field.
            //
            // We store sanitized versions in new variables so
            // the raw values are never used for display/output.
            //
            const cleanName    = sanitizeInput(rawName);
            const cleanRoll    = sanitizeInput(rawRoll);

            // (Feedback fields are sanitized inside buildModuleCard
            //  and also when building the teacher card below)


            // ── STEP 4: Capture star ratings ────────────────
            // Radio button values are controlled by us (1–5),
            // so these are already safe — but we still validate
            // they're expected numbers before using them.
            const ratingMod1    = getRating('sec-mod1-rating');
            const ratingMod2    = getRating('sec-mod2-rating');
            const ratingMod3    = getRating('sec-mod3-rating');
            const ratingMod4    = getRating('sec-mod4-rating');
            const ratingMod5    = getRating('sec-mod5-rating');
            const ratingMod6    = getRating('sec-mod6-rating');
            const ratingTeacher = getRating('sec-teacher-rating');


            // ── STEP 5: Debug log ────────────────────────────
            // We log sanitized data — good practice. Never log
            // raw unsanitized data in production.
            console.log("✅ Secure Sanitized Data:", {
                cleanName, cleanRoll,
                mod1: sanitizeInput(rawMod1), rating1: ratingMod1,
                mod2: sanitizeInput(rawMod2), rating2: ratingMod2,
                mod3: sanitizeInput(rawMod3), rating3: ratingMod3,
                mod4: sanitizeInput(rawMod4), rating4: ratingMod4,
                mod5: sanitizeInput(rawMod5), rating5: ratingMod5,
                mod6: sanitizeInput(rawMod6), rating6: ratingMod6,
                teacher: sanitizeInput(rawTeacher), ratingT: ratingTeacher
            });


            // ── STEP 6: DEFENSE LAYER 4 — Build output safely
            //
            // We now construct the output panel using DOM methods.
            // CRITICAL RULE: We NEVER use innerHTML with user data.
            // We use createElement + textContent throughout.
            //
            // First, clear any previous output safely.
            outputContent.textContent = ''; // ✅ Clears safely, no HTML parsing


            // ── Security Notice Banner ───────────────────────
            // This banner is static text — safe to build directly.
            const securityBanner = document.createElement('div');
            securityBanner.style.cssText = `
                background: rgba(34,197,94,0.1);
                border: 1px solid rgba(34,197,94,0.3);
                border-radius: 8px;
                padding: 10px 14px;
                margin-bottom: 20px;
                font-size: 0.78rem;
                color: #86efac;
            `;
            // ✅ Static string — safe to use textContent
            securityBanner.textContent =
                '✅ Secure Version: Input has been sanitized and encoded. ' +
                'Malicious scripts in feedback fields are neutralized.';
            outputContent.appendChild(securityBanner);


            // ── Student Info Block ───────────────────────────
            const studentBlock = document.createElement('div');
            studentBlock.style.cssText = `
                margin-bottom: 20px;
                padding-bottom: 16px;
                border-bottom: 1px solid #334155;
            `;

            // Label: "Student"
            const studentLabel = document.createElement('p');
            studentLabel.style.cssText = `
                font-size: 0.75rem;
                text-transform: uppercase;
                letter-spacing: 0.06em;
                color: #64748b;
                margin-bottom: 4px;
            `;
            studentLabel.textContent = 'Student'; // ← static, safe

            // Student name — SANITIZED and set via textContent
            const studentNameEl = document.createElement('p');
            studentNameEl.style.cssText = `
                font-size: 1.1rem;
                font-weight: 700;
                color: #f1f5f9;
            `;
            studentNameEl.textContent = cleanName; // ✅ sanitized + textContent

            studentBlock.appendChild(studentLabel);
            studentBlock.appendChild(studentNameEl);

            // Roll number (optional field)
            if (cleanRoll) {
                const rollEl = document.createElement('p');
                rollEl.style.cssText = 'font-size:0.85rem; color:#94a3b8; margin-top:2px;';
                rollEl.textContent = 'Roll No: ' + cleanRoll; // ✅ sanitized + textContent
                studentBlock.appendChild(rollEl);
            }

            outputContent.appendChild(studentBlock);


            // ── Section Label: Module Ratings ───────────────
            const moduleLabel = document.createElement('p');
            moduleLabel.style.cssText = `
                font-size: 0.78rem;
                text-transform: uppercase;
                letter-spacing: 0.06em;
                color: #64748b;
                margin-bottom: 12px;
            `;
            moduleLabel.textContent = 'Module Ratings & Feedback'; // ← static, safe
            outputContent.appendChild(moduleLabel);


            // ── Build Each Module Card ───────────────────────
            // buildModuleCard() uses textContent internally.
            // All user data is sanitized + escaped inside it.
            const modules = [
                { name: 'Module 1 — Basics of Number Theory and Security', rating: ratingMod1, feedback: rawMod1 },
                { name: 'Module 2 — Symmetric Ciphers',                    rating: ratingMod2, feedback: rawMod2 },
                { name: 'Module 3 — Asymmetric Ciphers and Key Distribution', rating: ratingMod3, feedback: rawMod3 },
                { name: 'Module 4 — Cryptographic Data Integrity Concepts', rating: ratingMod4, feedback: rawMod4 },
                { name: 'Module 5 — Network and Internet Security',         rating: ratingMod5, feedback: rawMod5 },
                { name: 'Module 6 — Cloud and IoT Security',                rating: ratingMod6, feedback: rawMod6 },
            ];

            modules.forEach(mod => {
                const card = buildModuleCard(mod.name, mod.rating, mod.feedback);
                outputContent.appendChild(card);
            });


            // ── Teacher Rating Section ───────────────────────
            const teacherLabel = document.createElement('p');
            teacherLabel.style.cssText = `
                font-size: 0.78rem;
                text-transform: uppercase;
                letter-spacing: 0.06em;
                color: #64748b;
                margin-top: 8px;
                margin-bottom: 12px;
            `;
            teacherLabel.textContent = 'Teacher Rating & Feedback'; // ← static
            outputContent.appendChild(teacherLabel);

            // Teacher card — built with createElement + textContent
            const teacherCard = document.createElement('div');
            teacherCard.style.cssText = `
                background: #0f172a;
                border-radius: 8px;
                padding: 14px 18px;
                border-left: 3px solid #a78bfa;
            `;

            const teacherHeader = document.createElement('div');
            teacherHeader.style.cssText = `
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 6px;
            `;

            const teacherName = document.createElement('span');
            teacherName.style.cssText = 'font-size:0.8rem; font-weight:700; color:#c4b5fd;';
            teacherName.textContent = 'Ms. Anita John'; // ← static string, safe

            const teacherStars = document.createElement('span');
            teacherStars.style.cssText = 'color:#facc15; font-size:1rem;';
            teacherStars.textContent = buildStars(ratingTeacher); // ← textContent: safe

            teacherHeader.appendChild(teacherName);
            teacherHeader.appendChild(teacherStars);

            const teacherFeedbackEl = document.createElement('div');
            teacherFeedbackEl.style.cssText = 'font-size:0.88rem; color:#94a3b8;';

            if (rawTeacher && rawTeacher.trim()) {
                // ✅ Sanitized then set via textContent
                teacherFeedbackEl.textContent = sanitizeInput(rawTeacher);
            } else {
                teacherFeedbackEl.style.cssText += ' color:#475569; font-style:italic;';
                teacherFeedbackEl.textContent = 'No feedback provided.';
            }

            teacherCard.appendChild(teacherHeader);
            teacherCard.appendChild(teacherFeedbackEl);
            outputContent.appendChild(teacherCard);


            // ── STEP 7: Show the output panel ───────────────
            outputArea.style.display = 'block';
            outputArea.scrollIntoView({ behavior: 'smooth', block: 'start' });

            // ── STEP 8: Success notification ─────────────────
            showToast('✅ Feedback submitted! (Sanitized & Encoded)', 'success');
        });
    }


    // ════════════════════════════════════════════════════════
    // RESET BUTTON
    // ════════════════════════════════════════════════════════
    //
    // Clears all form fields and hides the output panel.
    // We use .value = '' and .textContent = '' — both safe.
    // We NEVER use innerHTML for clearing or resetting.
    //
    if (resetBtn) {
        resetBtn.addEventListener('click', () => {

            // Clear text input fields
            document.getElementById('sec-student-name').value = '';
            document.getElementById('sec-student-roll').value = '';

            // Clear all textarea feedback fields
            ['mod1','mod2','mod3','mod4','mod5','mod6','teacher'].forEach(key => {
                const ta = document.getElementById(`sec-feedback-${key}`);
                if (ta) ta.value = '';
            });

            // Uncheck all star radio buttons
            document.querySelectorAll('input[type="radio"]').forEach(r => {
                r.checked = false;
            });

            // ✅ Clear output safely — textContent, not innerHTML
            outputArea.style.display    = 'none';
            outputContent.textContent   = '';

            showToast('🔄 Form reset.', 'warning');
        });
    }

});

// ════════════════════════════════════════════════════════════
// SUMMARY: WHAT THIS FILE DOES vs THE VULNERABLE VERSION
// ════════════════════════════════════════════════════════════
//
//  VULNERABLE VERSION (script_vuln.js)      SECURE VERSION (script_secure.js)
//  ──────────────────────────────────────   ─────────────────────────────────
//  outputContent.innerHTML = `...${input}`  outputEl.textContent = input
//  No validation on name field              validateName() checks format
//  Raw input embedded in HTML string        sanitizeInput() strips tags/JS
//  <script> tags manually re-executed       createElement never runs scripts
//  XSS payloads execute as code             XSS payloads display as plain text
//
//  RESULT: The secure version renders payloads like:
//    <script>alert("XSS")</script>
//  as literal visible text — never executes them.
//
// ════════════════════════════════════════════════════════════
