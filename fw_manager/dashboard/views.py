from django.shortcuts import render, redirect
from dashboard.models import BlockedIP, ThreatLog, FirewallRule
import subprocess
from dashboard.forms import FirewallRuleForm

# Create your views here.


def dashboard_home(request):
    """
    Render the dashboard home page.
    """
    blocked_ips = BlockedIP.objects.all().order_by("-blocked_at")[:50]
    recent_logs = ThreatLog.objects.all().order_by("-timestamp")[:20]

    return render(
        request,
        "dashboard/home.html",
        {"blocked_ips": blocked_ips, "recent_logs": recent_logs},
    )


def list_rules(request):
    """
    View to list all stored rules
    """
    rules = FirewallRule.objects.all()
    return render(request, "dashboard/list_rules.html", {"rules": rules})


def add_rule(request):
    """
    View to list add a rule
    """
    if request.method == "POST":
        form = FirewallRuleForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect("list_rules")
    else:
        form = FirewallRuleForm()
    return render(request, "dashboard/add_rule.html", {"form": form})


def delete_rule(request, rule_id):
    """
    View to list delete a rule
    """
    FirewallRule.objects.filter(id=rule_id).delete()
    return redirect("list_rules")


def apply_rules(request):
    """
    Apply rules to iptables
    """
    rules = FirewallRule.objects.all()
    subprocess.run(["sudo", "iptables", "-F"])  # flush rules

    for rule in rules:
        cmd = [
            "sudo",
            "iptables",
            "-A",
            rule.direction,
            "-p",
            rule.protocol,
            "--dport",
            str(rule.port),
            "-j",
            rule.action,
        ]
        subprocess.run(cmd)

    return render(request, "dashboard/apply_result.html", {"rules": rules})


def list_applied_rules(request):
    """
    List current applied iptables rules
    """
    result = subprocess.run(["sudo", "iptables", "-L"], capture_output=True, text=True)
    return render(request, "dashboard/applied_rules.html", {"output": result.stdout})
