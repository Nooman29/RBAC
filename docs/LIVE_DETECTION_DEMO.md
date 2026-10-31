# Live detection demo (presentation script)

Shows the three detection layers on the running system, using real sign-ins:

1. **Rules** catch known warning signs on the request that shows them (R1-R4).
2. **The model** scores the session while it is still running (R5, provisional).
3. **The end-of-session score** stays the official verdict; administrator verdicts feed back into R4.

Time needed: about 8 minutes. Screenshots of a full run, as a fallback, are in
`docs/evaluation/2026-10-31-live-detection/screenshots/`.

## Before the presentation (10 minutes)

1. Start the system and check it:
   ```powershell
   docker compose up -d
   curl.exe http://127.0.0.1:8000/health
   ```
2. Create the demo accounts. Sign-in codes are emailed to plus-addresses of your own email
   (you+live_staff@gmail.com), so have your inbox open during the demo:
   ```powershell
   docker compose exec backend python -m scripts.setup_live_demo --email-base you@gmail.com --password "Demo#2026"
   ```
   Re-run the same command before every rehearsal: it deletes the earlier `live_` accounts and starts clean.
   It never touches real accounts.
3. Use **two separate browsers**, because the sign-in is stored per browser:
   - **Browser A (Chrome)**: sign in as `live_admin`, open **Alerts**. The **In progress** panel at the top
     refreshes every 10 seconds.
   - **Browser B (Edge, or a Chrome incognito window)**: the "user" side. Sign in and out of each demo account here.
4. Present during the day (07:00-19:00 Nairobi time). R3 is set up for a daytime demo, and after 19:00 the
   accounts without history would also raise "unusual hour".

| Account | Role | Prepared history | Shows |
|---|---|---|---|
| live_admin | Administrator | none | the dashboard you present from |
| live_staff | Standard User | none | R1 |
| live_night | Standard User | 6 night shifts, 22:00-01:00 | R3 |
| live_operator | Administrator | 8 quiet daytime sessions (only reads) + 1 session confirmed as a threat for "many writes" | R4, R2, R5, then the final verdict |
| live_victim_1 to 5 | Standard User | none | throwaway accounts for live_operator to delete |

Always delete the `live_victim_` accounts, never real ones: deleting a user also deletes their whole history,
which the model trains on.

## The demo

### 1. R1, action outside the user's access (about 1 minute)

Browser B: sign in as **live_staff**. The menu shows only what this role may use; there is no Users page.

Type `http://127.0.0.1:5173/users` in the address bar and press Enter. A "permission denied" banner appears.
Do it **three times**.

Browser A: within 10 seconds, **Action outside the user's access**, medium, "3 refused requests in 10 min".

*Say:* "The interface hides what a role cannot use, and the server refuses it anyway. Someone who goes around the
menu, by typing addresses or replaying a stolen token against the API, produces refused requests. One refusal can be
a mistake; three in ten minutes is probing. Refused requests are never fed to the model, so they cannot distort
its features."

Click **Terminate**. In Browser B, click any link: the user is sent back to the sign-in page ("terminated").

### 2. R3, unusual hour for this user (about 1 minute)

Browser B: sign in as **live_night**. The dashboard opens.

Browser A: **Unusual hour for this user**, low, "Active at HH:00 EAT, outside this user's usual hours".

*Say:* "This account has only ever worked night shifts. The rule compares the hour of each action with the hours
this user has actually worked before, in Nairobi time. A user with fewer than five past sessions is in a learning
period: they are compared with business hours instead, and the alert says so."

Click **Dismiss** (it was just a shift change). Sign out in Browser B.

### 3. R4, R2 and R5 on one session (about 3 minutes)

Browser B: sign in as **live_operator** and open **Users**.

**Delete live_victim_1.**
Browser A: **Repeat of a confirmed threat pattern**, high, "highwrite".

*Say:* "Weeks ago an administrator reviewed one of this user's sessions, a burst of account changes, and marked
it a confirmed threat. That verdict became a rule: the first write in a session that normally only reads repeats
that pattern, and the system flags it straight away, mid-session."

**Delete live_victim_2 to live_victim_5** (all five within two minutes).
Browser A: **Burst of deletions/exports**, high, "5 deletion(s) ... in 2 min". High-risk roles (Finance Officer,
Programme Administrator, Auditor) trigger at 3.

Click around a little in Browser B (Sessions, Alerts, Users) until about 10 actions have been made.
Browser A: **Model (provisional)**, high, "Model score 0.6.. is above the standard-tier threshold 0.5..",
with the top factors.

*Say:* "This one is not a rule. It is the Isolation Forest scoring the session so far, with the same features,
the same per-role threshold and the same SHAP explanation as the final score. It waits for ten actions or five
minutes, because any session looks odd in its first minute, and scores at most once a minute so requests stay
fast."

### 4. Stop it and show the verdict (about 2 minutes)

Browser A: click **Terminate** on any live_operator row. Browser B is signed out on its next click.

In the Alerts list below the panel, open the newest alert for live_operator. Show:
- **Terminated by an administrator**
- **Live detection during this session**: provisional score next to the **final score (official)**
- the three live alerts, now marked `terminated`
- **Why this was flagged**: the SHAP explanation

*Say:* "Live checks are early warnings so the administrator can act in time. When the session ends, the full
session is scored as before and that is the verdict. The administrator's review of it feeds back into the rules,
which is how R4 knew about this user."

## If something goes wrong

| Problem | Fix |
|---|---|
| No email code | Check spam; codes expire after 5 minutes. As a last resort, show the screenshots. |
| A live alert does not appear | Wait for the 10-second refresh, or click Refresh in Sessions. Check that you are acting in the account named above. |
| R3 does not fire | The demo is outside 07:00-19:00, or live_night's history overlaps the current hour. Re-run the setup script. |
| R5 does not fire | Make a few more actions and wait a minute (it scores at most once a minute). The score depends on the trained model; if it stays below the threshold, show the provisional score on the alert page, which is still recorded. |
| Deleting a victim fails | It was already deleted in a rehearsal: re-run the setup script. |

## After the presentation

```powershell
docker compose exec backend python -m scripts.setup_live_demo --remove --yes
```
