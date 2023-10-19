## Using the Vul Operator through Microk8s 

[Microk8s](https://microk8s.io/) is a lightweight Kubernetes distribution that can be used on your personal machine, Raspberry Pi cluster, in data centres or edge devices; just to name a few use cases.

One of the benefits of using microk8s is its add-on ecosystem. Once you have microk8s installed, you can spin up a variety of cloud native projects directly in your cluster through merely one command:

```
microk8s enable <name of the addon>
```

A list of addons is provided below.
```
    dashboard-ingress    # (community) Ingress definition for Kubernetes dashboard
    jaeger               # (community) Kubernetes Jaeger operator with its simple config
    knative              # (community) Knative Serverless and Event Driven Applications
    linkerd              # (community) Linkerd is a service mesh for Kubernetes and other frameworks
    multus               # (community) Multus CNI enables attaching multiple network interfaces to pods
    openebs              # (community) OpenEBS is the open-source storage solution for Kubernetes
    osm-edge             # (community) osm-edge is a lightweight SMI compatible service mesh for the edge-computing.
    portainer            # (community) Portainer UI for your Kubernetes cluster
    vul-operator       # (community) Kubernetes-native security toolkit
    traefik              # (community) traefik Ingress controller for external access
    dns                  # (core) CoreDNS
    ha-cluster           # (core) Configure high availability on the current node
    helm                 # (core) Helm - the package manager for Kubernetes
    helm3                # (core) Helm 3 - the package manager for Kubernetes
    vul                # (core) Kubernetes-native security scanner
    cert-manager         # (core) Cloud native certificate management
    dashboard            # (core) The Kubernetes dashboard
    host-access          # (core) Allow Pods connecting to Host services smoothly
    hostpath-storage     # (core) Storage class; allocates storage from host directory
    ingress              # (core) Ingress controller for external access
    kube-ovn             # (core) An advanced network fabric for Kubernetes
    mayastor             # (core) OpenEBS MayaStor
    metallb              # (core) Loadbalancer for your Kubernetes cluster
    metrics-server       # (core) K8s Metrics Server for API access to service metrics
    observability        # (core) A lightweight observability stack for logs, traces and metrics
    prometheus           # (core) Prometheus operator for monitoring and logging
    rbac                 # (core) Role-Based Access Control for authorisation
    registry             # (core) Private image registry exposed on localhost:32000
    storage              # (core) Alias to hostpath-storage add-on, deprecated
```

This tutorial will showcase how to install and then remove the Vul Operator addon.

## Prerequisites

You need to have microk8s installed. In our case, we have set up kubectl to use the microk8s cluster. You can find different guides, depending on your operating system, on the [microk8s website.](https://microk8s.io/tutorials)

## Install the Vul Operator 

To install the Vul Operator, simply run the following command:
```
microk8s enable vul
```

The confirmation should be similar to the following output:
```
Infer repository core for addon vul
Infer repository core for addon helm3
Addon core/helm3 is already enabled
Infer repository core for addon dns
Addon core/dns is already enabled
Installing Vul
"khulnasoft" already exists with the same configuration, skipping
Release "vul-operator" does not exist. Installing it now.
NAME: vul-operator
LAST DEPLOYED: Sat Oct  8 16:39:59 2022
NAMESPACE: vul-system
STATUS: deployed
REVISION: 1
TEST SUITE: None
NOTES:
You have installed Vul Operator in the vul-system namespace.
It is configured to discover Kubernetes workloads and resources in
all namespace(s).

Inspect created VulnerabilityReports by:

    kubectl get vulnerabilityreports --all-namespaces -o wide

Inspect created ConfigAuditReports by:

    kubectl get configauditreports --all-namespaces -o wide

Inspect the work log of vul-operator by:

    kubectl logs -n vul-system deployment/vul-operator
Vul is installed
```

You should now see the Vul Operator pod running inside of the `vul-system` namespace:
```
kubectl get all -n vul-system
NAME                                            READY   STATUS    RESTARTS   AGE
pod/vul-operator-57c44575c4-ml2hw             1/1     Running   0          29s
pod/scan-vulnerabilityreport-5d55f55cd7-7l6kn   1/1     Running   0          27s

NAME                     TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)   AGE
service/vul-operator   ClusterIP   None         <none>        80/TCP    29s

NAME                             READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/vul-operator   1/1     1            1           29s

NAME                                        DESIRED   CURRENT   READY   AGE
replicaset.apps/vul-operator-57c44575c4   1         1         1       29s

NAME                                            COMPLETIONS   DURATION   AGE
job.batch/scan-vulnerabilityreport-5d55f55cd7   0/1           27s        27s
```

If you have any container images running in your microk8s cluster, Vul will start a vulnerability scan on those right away. 

## Cleaning up

Removing the Vul Operator from your cluster is as easy as installing it. Simply run:
```
microk8s disable vul
```

You should see an output similar to the following:
```
Infer repository core for addon vul
Disabling Vul
release "vul-operator" uninstalled
Vul disabled
```

