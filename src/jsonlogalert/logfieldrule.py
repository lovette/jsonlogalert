from __future__ import annotations

import operator
import re
from collections.abc import Sequence

from click import ClickException, echo

_RULE_OPERATORS = {
    "=": operator.eq,
    "!": operator.ne,
    "!=": operator.ne,
    "~": None,
    "!~": None,
    ">": operator.gt,
    "<": operator.lt,
    ">=": operator.ge,
    "<=": operator.le,
}

# Two-character operators must go first (so if a rule begins with `!=` it's not confused with `!`)
_RULE_OPERATORS = {key: _RULE_OPERATORS[key] for key in sorted(_RULE_OPERATORS.keys(), key=len, reverse=True)}


######################################################################
# FieldRuleError


class FieldRuleError(ClickException):
    """Illegal field rule exception."""


######################################################################
# FieldRule


class FieldRule:
    """Field rule base class."""

    RULE_OPERATORS = _RULE_OPERATORS

    def __init__(self, rule_op: str, rule_value: str | float | Sequence | None = None) -> None:
        """Constructor.

        Args:
            rule_op (str): Rule operator (=, !=, etc.)
            rule_value (str | float | Sequence | None, optional): Rule value. Defaults to None.
        """
        self.rule_op = rule_op
        self.rule_negate = False
        self.rule_value = rule_value

        if rule_op.startswith("!"):
            self.rule_op = rule_op.removeprefix("!") or "="
            self.rule_negate = True

        assert self.rule_op in self.RULE_OPERATORS

    def __repr__(self) -> str:
        """Return the “official” string representation of an object.

        Returns:
            str
        """
        class_name = type(self).__name__
        negate = "!" if self.rule_negate else ""
        return f"{class_name}({negate}{self.rule_op}{self.rule_value!r})"

    def __str__(self) -> str:
        """Return string representation of an object used in print().

        Returns:
            str
        """
        negate = "!" if self.rule_negate else ""
        return f"{negate}{self.rule_op}{self.rule_value!r}"

    @staticmethod
    def assert_values_type(rule_values: list, assert_type: type) -> None:
        """Raise exception if values are not of given type.

        Args:
            rule_values (list): List of values.
            assert_type (type): Type to assert.

        Raises:
            FieldRuleError
        """
        for v in rule_values:
            if not isinstance(v, assert_type):
                raise FieldRuleError(f"'{v}': Unexpected value type {type(v).__name__}; expected {assert_type.__name__}")

    @staticmethod
    def cast_values_scalar(rule_values: list) -> None:
        """Cast values to an int or float.

        Args:
            rule_values (list): List of values.

        Raises:
            FieldRuleError
        """
        for i, v in enumerate(rule_values):
            if not isinstance(v, (int, float)):
                try:
                    v_scalar = float(v) if "." in v else int(v)
                except ValueError as err:
                    raise FieldRuleError(f"'{v}': Unexpected value type {type(v).__name__}; cannot cast to scalar value") from err
                else:
                    rule_values[i] = v_scalar

    @staticmethod
    def build_rules(rules_config: list[dict[str, str | float | bool]]) -> tuple[dict[str, FieldRule]] | None:  # noqa: C901
        """Build rules for a configuration.

        Args:
            rules_config (list): Blocks of field rules.

        Returns:
            tuple[dict[str, FieldRule]]
        """
        if not rules_config:
            return None

        def _build_field_rules(rule_op: str, rule_values: list) -> FieldRule:
            """Build rule for an individual field."""
            assert isinstance(rule_values, Sequence)

            first_value = rule_values[0]
            single_value = len(rule_values) == 1

            if first_value == "*":
                field_rule = FieldRuleHasField(rule_op)
            elif rule_op[0] in (">", "<"):
                FieldRule.cast_values_scalar(rule_values)
                field_rule = FieldRuleOperator(rule_op, rule_values)
            elif rule_op.endswith("~"):
                rule_cls = FieldRuleRegex if single_value else FieldRuleRegexList
                field_rule = rule_cls(rule_op, rule_values)
            else:
                rule_cls = FieldRuleOperator if single_value else FieldRuleOperatorList
                field_rule = rule_cls(rule_op, rule_values)

            return field_rule

        def _build_block_rules(field_block: dict) -> dict[str, FieldRule]:  # noqa: C901
            """Build ruleset for an individual block of field rules."""
            assert isinstance(field_block, dict)

            field_fns = {}
            rule_op_value = None

            for rule_field, rule_value in field_block.items():
                rule_op = None
                rule_op_value = rule_value

                if isinstance(rule_op_value, list):
                    if len(rule_op_value) > 1:
                        # First item can be an operator
                        for op in FieldRule.RULE_OPERATORS:
                            if rule_op_value[0] == op:
                                rule_op = op
                                rule_op_value.pop(0)
                                break
                elif isinstance(rule_op_value, str):
                    for op in FieldRule.RULE_OPERATORS:
                        if rule_op_value.startswith(op):
                            rule_op = op
                            rule_op_value = rule_op_value.removeprefix(op)
                            break
                    rule_op_value = [rule_op_value]
                else:
                    rule_op_value = [rule_op_value]

                if not rule_op:
                    rule_op = "="

                try:
                    field_fns[rule_field] = _build_field_rules(rule_op, rule_op_value)
                except FieldRuleError as err:
                    raise FieldRuleError(f"{rule_field}: {err}") from err

            return field_fns

        if not isinstance(rules_config, list):
            rules_config = [rules_config]

        rules_list: list[dict] = [_build_block_rules(field_block) for field_block in rules_config]

        return tuple(rules_list) or None

    @staticmethod
    def match_rules(fields: dict, block_rules_list: list[dict[str, FieldRule]]) -> bool:
        """Evaluates list of rule blocks against log entry fields.

        Args:
            fields (dict): Log entry fields.
            block_rules_list (list[dict[str, FieldRule]]): List of field blocks rules.

        Returns:
            bool: True if all the rules for *any* field block are True.
        """

        def _match_block_rules(fields: dict, block_rules: dict[str, FieldRule]) -> bool:
            """Return True if the rules for *all* fields are True."""
            assert isinstance(block_rules, dict)

            for field_name, field_rule in block_rules.items():
                field_value = fields.get(field_name)
                if not field_rule(field_value):
                    # All fields in the block must match
                    return False

            return True

        assert isinstance(block_rules_list, Sequence)

        # Any block in the list can match
        return any(_match_block_rules(fields, block_rules) for block_rules in block_rules_list)

    @staticmethod
    def print_rules(block_rules_list: list[dict[str, FieldRule]]) -> None:
        """Print list of rule blocks for debugging.

        Args:
            block_rules_list (list[dict[str, FieldRule]]): List of field blocks rules.
        """

        def _print_block_rules(block_rules: dict[str, FieldRule]) -> None:
            assert isinstance(block_rules, dict)

            for i, (field_name, field_rule) in enumerate(block_rules.items()):
                if not i:
                    echo(f"    {field_name} {field_rule}")
                else:
                    echo(f"    and {field_name} {field_rule}")

        assert isinstance(block_rules_list, Sequence)

        for i, block_rules in enumerate(block_rules_list):
            if i:
                echo("  --or--")
            _print_block_rules(block_rules)


######################################################################
# FieldRuleOperator


class FieldRuleOperatorList(FieldRule):
    """Field rule that evaluates a basic comparison operator against a list of values."""

    def __init__(self, rule_op: str, rule_values: Sequence) -> None:
        """Constructor.

        Args:
            rule_op (str): Rule operator.
            rule_values (Sequence): List of values.
        """
        super().__init__(rule_op, rule_values)

        self.rule_fn = self.RULE_OPERATORS[self.rule_op]
        assert self.rule_fn is not None

    def __call__(self, *args, **kwds) -> bool:  # noqa: ARG002
        """Evaluate rule.

        Returns:
            bool: True if rule matches.
        """
        found_match = False

        for v in self.rule_value:
            if self.rule_fn(args[0], v):
                found_match = True
                break

        return not found_match if self.rule_negate else found_match


class FieldRuleOperator(FieldRuleOperatorList):
    """Field rule that evaluates a basic comparison operator against a single value."""

    def __init__(self, rule_op: str, rule_values: Sequence) -> None:
        """Constructor.

        Args:
            rule_op (str): Rule operator.
            rule_values (Sequence): List of values; only the first is used.
        """
        super().__init__(rule_op, rule_values)

        self.rule_value = self.rule_value[0]

    def __call__(self, *args, **kwds) -> bool:  # noqa: ARG002
        """Evaluate rule.

        Returns:
            bool: True if rule matches.
        """
        found_match = self.rule_fn(args[0], self.rule_value)

        return not found_match if self.rule_negate else found_match


######################################################################
# FieldRuleRegex


class FieldRuleRegexList(FieldRule):
    """Field rule that evaluates a regular expression against a list of values."""

    def __init__(self, rule_op: str, rule_values: Sequence) -> None:
        """Constructor.

        Args:
            rule_op (str): Rule operator.
            rule_values (Sequence): List of (raw) regular expressions.
        """
        super().__init__(rule_op, rule_values)

        try:
            self.rule_re = tuple(re.compile(v) for v in rule_values)
        except TypeError as err:
            FieldRule.assert_values_type(rule_values, str)
            raise FieldRuleError(f"{err}") from err

    def __call__(self, *args, **kwds) -> bool:  # noqa: ARG002
        """Evaluate rule.

        Returns:
            bool: True if rule matches.
        """
        found_match = False

        for r in self.rule_re:
            if r.match(str(args[0])):
                found_match = True
                break

        return not found_match if self.rule_negate else found_match


class FieldRuleRegex(FieldRuleRegexList):
    """Field rule that evaluates a regular expression against a single value."""

    def __init__(self, rule_op: str, rule_values: Sequence) -> None:
        """Constructor.

        Args:
            rule_op (str): Rule operator.
            rule_values (Sequence): List of (raw) regular expressions; only the first is used.
        """
        super().__init__(rule_op, rule_values)

        self.rule_re = self.rule_re[0]

    def __call__(self, *args, **kwds) -> bool:  # noqa: ARG002
        """Evaluate rule.

        Returns:
            bool: True if rule matches.
        """
        found_match = self.rule_re.match(str(args[0]))

        return not found_match if self.rule_negate else found_match


######################################################################
# FieldRuleHasField


class FieldRuleHasField(FieldRule):
    """Field rule that evaluates whether a log entry defines a value for a field."""

    def __init__(self, rule_op: str) -> None:
        """Constructor.

        Args:
            rule_op (str): Rule operator.
        """
        super().__init__(rule_op)

    def __repr__(self) -> str:
        """String representation of object.

        Returns:
            str:
        """
        class_name = type(self).__name__
        return f"{class_name}({self.rule_negate is False})"

    def __call__(self, *args, **kwds) -> bool:  # noqa: ARG002
        """Evaluate rule.

        Returns:
            bool: True if rule matches.
        """
        return args[0] is None if self.rule_negate else args[0] is not None
