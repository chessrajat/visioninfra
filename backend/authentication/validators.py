import re

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


class StrongPasswordValidator:
    def validate(self, password, user=None):
        if len(password) < 12:
            raise ValidationError(_("Password must be at least 12 characters long."))
        if not re.search(r"[A-Z]", password):
            raise ValidationError(_("Password must include an uppercase letter."))
        if not re.search(r"[a-z]", password):
            raise ValidationError(_("Password must include a lowercase letter."))
        if not re.search(r"\d", password):
            raise ValidationError(_("Password must include a number."))
        if not re.search(r"[^A-Za-z0-9]", password):
            raise ValidationError(_("Password must include a symbol."))

    def get_help_text(self):
        return _("Use 12+ characters with upper, lower, number, and symbol.")
