#!/usr/bin/env bash
helm uninstall vul-operator  -n vul-system
kubectl delete crd vulnerabilityreports.khulnasoft-lab.github.io
kubectl delete crd configauditreports.khulnasoft-lab.github.io
kubectl delete crd clusterconfigauditreports.khulnasoft-lab.github.io
kubectl delete crd rbacassessmentreports.khulnasoft-lab.github.io
kubectl delete crd infraassessmentreports.khulnasoft-lab.github.io
kubectl delete crd clusterrbacassessmentreports.khulnasoft-lab.github.io
