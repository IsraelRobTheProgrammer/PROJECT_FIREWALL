from django import forms
from dashboard.models import FirewallRule


class FirewallRuleForm(forms.ModelForm):
    class Meta:
        model = FirewallRule
        fields = [
            "name",
            "action",
            "protocol",
            "source_ip",
            "dest_ip",
            "source_port",
            "dest_port",
            "port",
            "direction",
            "description",
        ]

    def clean(self):
        cleaned_data = super().clean()
        protocol = cleaned_data.get("protocol")
        port = cleaned_data.get("port")
        action = cleaned_data.get("action")
        direction = cleaned_data.get("direction")
        description = cleaned_data.get("description")

        if FirewallRule.objects.filter(
            protocol=protocol, port=port, action=action, direction=direction
        ).exists():
            raise forms.ValidationError("This rule already exists.")

        if port < 1 or port > 65535:
            raise forms.ValidationError("Port number must be between 1 and 65535.")
        if protocol not in ["tcp", "udp"]:
            raise forms.ValidationError("Protocol must be either 'tcp' or 'udp'.")
        if action not in ["ACCEPT", "DROP"]:
            raise forms.ValidationError("Action must be either 'ACCEPT' or 'DROP'.")
        if direction not in ["INPUT", "OUTPUT"]:
            raise forms.ValidationError("Direction must be either 'INPUT' or 'OUTPUT'.")
        if description and len(description) > 255:
            raise forms.ValidationError("Description must be 255 characters or less.")
