#!/usr/bin/env bash

SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")/..

CRD_DIR=$SCRIPT_ROOT/deploy/helm/crds
HELM_DIR=$SCRIPT_ROOT/deploy/helm
STATIC_DIR=$SCRIPT_ROOT/deploy/static

HELM_TMPDIR=$(mktemp -d)
trap "rm -rf $HELM_TMPDIR" EXIT

helm template vul-operator $HELM_DIR \
  --namespace vul-system \
  --set="managedBy=kubectl" \
  --output-dir=$HELM_TMPDIR

cat $CRD_DIR/* > $STATIC_DIR/vul-operator.yaml

## if namespace.yaml do not exist, cat namespace.yaml to vul-operator.yaml (avoid duplicate namespace definition)
[ ! -f $HELM_TMPDIR/vul-operator/templates/namespace.yaml ] && cat $STATIC_DIR/namespace.yaml >> $STATIC_DIR/vul-operator.yaml

cat $HELM_TMPDIR/vul-operator/templates/rbac/* > $STATIC_DIR/rbac.yaml
cp $STATIC_DIR/rbac.yaml $HELM_TMPDIR/vul-operator/templates
cat $HELM_TMPDIR/vul-operator/templates/serviceaccount.yaml >> $STATIC_DIR/rbac.yaml
rm -rf $HELM_TMPDIR/vul-operator/templates/rbac

cat $HELM_TMPDIR/vul-operator/templates/configmaps/* > $STATIC_DIR/config.yaml
cat $HELM_TMPDIR/vul-operator/templates/secrets/* >> $STATIC_DIR/config.yaml
cp $STATIC_DIR/config.yaml $HELM_TMPDIR/vul-operator/templates
rm -rf $HELM_TMPDIR/vul-operator/templates/configmaps
rm -rf $HELM_TMPDIR/vul-operator/templates/secrets

cat $HELM_TMPDIR/vul-operator/templates/specs/* > $STATIC_DIR/specs.yaml
rm -rf $HELM_TMPDIR/vul-operator/templates/specs

[ -d $HELM_TMPDIR/vul-operator/templates/vul-server ] && cat $HELM_TMPDIR/vul-operator/templates/vul-server/* > $STATIC_DIR/vul-server.yaml && cp $STATIC_DIR/vul-server.yaml $HELM_TMPDIR/vul-operator/templates
rm -rf $HELM_TMPDIR/vul-operator/templates/vul-server

cat $HELM_TMPDIR/vul-operator/templates/monitor/* > $STATIC_DIR/monitor.yaml
cp $STATIC_DIR/monitor.yaml $HELM_TMPDIR/vul-operator/templates
rm -rf $HELM_TMPDIR/vul-operator/templates/monitor


cat $HELM_TMPDIR/vul-operator/templates/* >> $STATIC_DIR/vul-operator.yaml

# Copy all manifests rendered by the Helm chart to the static resources directory,
# where they should be ignored by Git.
# This is done to support local development with partial updates to local cluster.

