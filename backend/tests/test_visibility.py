"""Dashboard visibility comes from role scope, not role name."""
from types import SimpleNamespace

from app.core.visibility import effective_scope, in_scope, visibility_scope


def _role(name, scope="own"):
    return SimpleNamespace(role_name=name, scope=scope)


def _user(roles, user_id=1, school_id=None, organization_id=None, department="Unassigned"):
    return SimpleNamespace(roles=roles, user_id=user_id, school_id=school_id,
                           organization_id=organization_id, department=department)


def test_original_roles_behave_as_before():
    assert visibility_scope(_user([_role("Administrator", "global")])) == {"level": "all"}
    assert visibility_scope(_user([_role("Manager", "department")], department="IT")) == \
        {"level": "department", "department": "IT"}
    assert visibility_scope(_user([_role("Standard User", "own")], user_id=7)) == {"level": "self", "user_id": 7}


def test_original_roles_still_scoped_when_the_column_is_at_its_default():
    # Old or test databases may hold the default 'own' on these rows.
    assert visibility_scope(_user([_role("Administrator", "own")])) == {"level": "all"}
    assert visibility_scope(_user([_role("Manager", "own")], department="HR"))["level"] == "department"


def test_school_scoped_roles_see_their_school():
    teacher = _user([_role("School Administrator", "school")], school_id="SCH-01")
    assert visibility_scope(teacher) == {"level": "school", "school_id": "SCH-01"}


def test_school_scope_without_a_school_falls_back_to_self():
    assert visibility_scope(_user([_role("Teacher", "school")], user_id=3)) == {"level": "self", "user_id": 3}


def test_supplier_sees_its_organisation():
    supplier = _user([_role("Supplier", "organization")], organization_id="ORG-9")
    assert visibility_scope(supplier) == {"level": "organization", "organization_id": "ORG-9"}


def test_dsfs_global_roles_see_everything():
    for name in ["Programme Administrator", "Finance Officer", "Auditor", "Logistics Officer"]:
        assert visibility_scope(_user([_role(name, "global")])) == {"level": "all"}


def test_widest_scope_wins_for_several_roles():
    user = _user([_role("Parent/Guardian", "own"), _role("School Staff", "school")], school_id="S1")
    assert effective_scope(user) == "school"


def test_unknown_scope_value_is_treated_as_own():
    assert effective_scope(_user([_role("Custom", "everything")])) == "own"


def test_in_scope_checks():
    scope = {"level": "school", "school_id": "S1"}
    assert in_scope(_user([], school_id="S1"), scope)
    assert not in_scope(_user([], school_id="S2"), scope)
    assert not in_scope(None, scope)
