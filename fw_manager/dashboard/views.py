from django.http import JsonResponse
from django.shortcuts import render, redirect
from dashboard.models import BlockedIP, ThreatLog, FirewallRule
from dashboard.forms import FirewallRuleForm
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_GET
from dpi.logs import get_logs, clear_logs
from dpi.runner import run_dpi, is_running, stop_dpi

import subprocess
import getpass
# Create your views here.


@login_required
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


@login_required
def list_rules(request):
    """
    View to list all stored rules
    """
    print(getpass.getuser())  # Logs the user that’s running Django

    rules = FirewallRule.objects.all()
    return render(request, "dashboard/list_rules.html", {"rules": rules})


@login_required
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


@login_required
def delete_rule(request, rule_id):
    """
    View to list delete a rule
    """
    FirewallRule.objects.filter(id=rule_id).delete()
    return redirect("list_rules")


@login_required
def apply_rules(request):
    """
    Apply rules to iptables
    """
    rules = FirewallRule.objects.all()
    subprocess.run(["sudo", "/usr/sbin/iptables", "-F"])  # flush rules
    flag_cmd = ["-C", "-A"]

    for rule in rules:
        cmd = [
            "sudo",
            "/usr/sbin/iptables",
            flag_cmd[0],  # Use -C to check if the rule exists
            rule.direction,
            "-p",
            rule.protocol,
        ]
        if rule.dest_port:
            cmd.extend(["--dport", str(rule.dest_port)])
        if rule.source_ip:
            cmd.extend(["-s", rule.source_ip])
        if rule.dest_ip:
            cmd.extend(["-d", rule.dest_ip])
        if rule.source_port:
            cmd.extend(["--sport", str(rule.source_port)])
        if rule.description:
            cmd.extend(["-m", "comment", "--comment", rule.description])

        cmd.extend(["-j", rule.action])

        print(cmd, "before check")
        result = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        if result.returncode != 0:  # Rule does not exist
            cmd[2] = flag_cmd[1]
            print(cmd, "after check")
            subprocess.run(cmd)
            messages.success(request, f"Applied rule: {rule}")
            print(f"[+] Applied rule: {cmd}")
        else:
            messages.info(request, f"Rule already applied: {rule}")
            print(f"[=] Already applied: {cmd}")

    return render(request, "dashboard/apply_result.html", {"rules": rules})


@login_required
def list_applied_rules(request):
    """
    List current applied iptables rules
    """
    result = subprocess.run(
        ["sudo", "/usr/sbin/iptables", "-L", "-v", "-n"], capture_output=True, text=True
    )
    return render(request, "dashboard/applied_rules.html", {"output": result.stdout})


@login_required
def dpi_control(request):
    """
    Control DPI capture
    """
    message = ""
    if request.method == "POST":
        action = request.POST.get("action")
        if action == "start":
            started = run_dpi()
            message = (
                "DPI Engine started successfully."
                if started
                else "DPI Engine is already running."
            )
        elif action == "stop":
            stop_dpi()
            # For now, we’ll just advise restarting Django to stop (Scapy sniffing is tricky to kill)
            message = "DPI Engine stopped successfully."

    return render(
        request,
        "dashboard/dpi_control.html",
        {
            "running": is_running(),
            "message": message,
        },
    )
    # if request.method == "POST":
    #     action = request.POST.get("action")
    #     if action == "start":
    #         subprocess.run(["sudo", "systemctl", "start", "dpi-capture"])
    #         messages.success(request, "DPI capture started.")
    #     elif action == "stop":
    #         subprocess.run(["sudo", "systemctl", "stop", "dpi-capture"])
    #         messages.success(request, "DPI capture stopped.")
    #     else:
    #         messages.error(request, "Invalid action.")

    # return render(request, "dashboard/dpi_control.html")


@require_GET
def fetch_logs(request):
    return JsonResponse(
        {
            "running": is_running(),
            "logs": get_logs(),
        }
    )


@login_required
def clear_logs_view(request):
    if request.method == "POST":
        clear_logs()
    return redirect("dpi_control")
