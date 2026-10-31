## Effect of reading hours in local time on real logins

Real sessions: 165 (closed, not simulated, not synthetic). Local time zone: Africa/Nairobi (EAT).
Before: model 20261031-095954 on UTC hours. After: model 20261031-100622 on local hours.

| Measure | Before (UTC hours) | After (local hours) |
|---|---|---|
| Logins counted as off-hours | 9.7% (16/165) | 20.0% (33/165) |
| Logins counted as weekend | 18.2% (30/165) | 18.2% (30/165) |
| Sessions flagged by the model | 10.9% (18/165) | 12.1% (20/165) |

UTC misread the off-hours flag for 27.3% (45/165) of real sessions:
- 14 business-hours logins in EAT that UTC called off-hours (early mornings)
- 31 off-hours logins in EAT that UTC called business hours (evenings)

Login hour of real sessions (count), UTC vs local (EAT):

| Hour | UTC | Local |
|---|---|---|
| 00:00 | 0 | 2 |
| 05:00 | 8 | 0 |
| 06:00 | 6 | 0 |
| 07:00 | 18 | 0 |
| 08:00 | 19 | 8 |
| 09:00 | 18 | 6 |
| 10:00 | 14 | 18 |
| 11:00 | 7 | 19 |
| 12:00 | 7 | 18 |
| 13:00 | 14 | 14 |
| 14:00 | 3 | 7 |
| 15:00 | 18 | 7 |
| 16:00 | 0 | 14 |
| 17:00 | 8 | 3 |
| 18:00 | 13 | 18 |
| 19:00 | 10 | 0 |
| 20:00 | 0 | 8 |
| 21:00 | 2 | 13 |
| 22:00 | 0 | 10 |
