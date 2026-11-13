# Security Notes

- 2026-11-13
  - `GET /recipes` → `200`, returns all recipes, including ones with `is_public: false`, with no authentication.
  - `PATCH /recipes/1` → `200`, title changed to "Totally Hacked Sauce." with no authentication.
  - `DELETE /recipes/1` → `204`, recipe removed; subsequent `GET /recipes` only returns recipes 2 and 3.