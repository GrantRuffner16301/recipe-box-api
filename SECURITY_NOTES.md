# Security Notes

- 2026-11-13
  - `GET /recipes` → `200`, returns all recipes, including ones with `is_public: false`, with no authentication.
  - `PATCH /recipes/1` → `200`, title changed to "Totally Hacked Sauce." with no authentication.
  - `DELETE /recipes/1` → `204`, recipe removed; subsequent `GET /recipes` only returns recipes 2 and 3.

**1. Overview**

- 2026-11-25   
- API: Recipe Box API
- Scope: authentication, authorization, password storage, and regression against earlier exploits.

**2. Authentication (`401` behavior)**

- **Protected endpoint tested:** `POST /recipes`
- **Cases:**
    - No `Authorization` header → response: `401`, body: `"Missing or invalid token"`
    - Malformed token (`this.is.not.a.real.token`) → `401`, body: `"Invalid token"`
    - Valid JWT (admin) → `201 Created`, recipe created successfully
- **Conclusion:** Protected endpoints correctly require a valid JWT; anonymous and invalid tokens are rejected.

**3. Authorization (`403` and roles/ownership)**

- **Endpoint tested:** `PATCH /recipes/3`
    - Token: user `4` (non-owner, role `user`) → `403 FORBIDDEN`, message: cannot modify others’ recipes
    - Token: user `3` (owner, role `admin`) → `200 OK`, recipe updated
- **Endpoint tested:** `GET /recipes/2`
    - Token: user `4` (non-owner) → `403 FORBIDDEN`, private recipe belongs to another user
    - Token: user `3` (owner/admin) → `200 OK`, recipe returned
- **Conclusion:** Ownership and role-based authorization enforced; non-owners blocked, admin/owner allowed.

**4. Public vs private recipe visibility**

- **Endpoint tested:** `GET /recipes`
    - No token → only public recipes shown (IDs `1`, `3`)
    - Token user `4` (non-owner) → only public recipes (IDs `1`, `3`)
    - Token user `3` (admin/owner) → public + private (IDs `1`, `2`, `3`, including private `id: 2`)
- **Conclusion:** Old exploit (“see all recipes without auth”) is fixed; private recipes hidden from non-owners.

**5. Password storage**

- **Table inspected:** `users` in `recipes.db`
- **Fields:** `id`, `username`, `email`, `password_hash`, `failed_logins`, `locked_until`, `role`
- **Observation:** `password_hash` contains Argon2id hashes (e.g. `$argon2id$v=19$m=65536,t=3,p=4$...`), no plaintext passwords.
- **Conclusion:** Passwords stored as Argon2id hashes; DB compromise does not reveal raw passwords.

**6. Regression against earlier exploits**

- Previous issue: listing all recipes, including private, without token.
- Current behavior:
    - `GET /recipes` with no token → only public recipes visible.
- **Conclusion:** Prior data exposure vulnerability no longer reproducible.

**7. Summary**

- Identity required on protected endpoints ✅
- Access correctly restricted by ownership and role ✅
- Passwords stored as secure hashes (Argon2id) ✅
- Known previous exploit attempts fail with `401` or `403` as expected ✅