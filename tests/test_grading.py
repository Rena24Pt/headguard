from headguard.grading import grade_for, meets


def test_thresholds():
    assert grade_for(100, 100) == "A+"
    assert grade_for(95, 100) == "A+"
    assert grade_for(90, 100) == "A"
    assert grade_for(75, 100) == "B"
    assert grade_for(60, 100) == "C"
    assert grade_for(45, 100) == "D"
    assert grade_for(30, 100) == "E"
    assert grade_for(10, 100) == "F"
    assert grade_for(0, 100) == "F"


def test_grade_scales_with_max_score():
    assert grade_for(50, 50) == "A+"
    assert grade_for(0, 0) == "F"


def test_meets():
    assert meets("A+", "B")
    assert meets("B", "B")
    assert not meets("C", "B")
    assert not meets("F", "E")
