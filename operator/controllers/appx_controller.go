/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	appxv1 "github.com/naturelr/code-example/operator/api/v1"
)

// AppxReconciler reconciles a Appx object
type AppxReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

//+kubebuilder:rbac:groups=appx.naturelr.cc,resources=appxes,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=appx.naturelr.cc,resources=appxes/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=appx.naturelr.cc,resources=appxes/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Appx object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.10.0/pkg/reconcile
func (r *AppxReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)
	l.Info(fmt.Sprint("==============", req.Name, req.Namespace, req.NamespacedName, req.String(), "==============="))

	// 获取cr
	appx := &appxv1.Appx{}
	if err := r.Get(ctx, req.NamespacedName, appx); err != nil {
		return ctrl.Result{}, err
	}
	r.Recorder.Event(appx, apiv1.EventTypeNormal, "找到cr", appx.Name)
	l.V(0).Info("cr appx:", "port", appx.Spec.Port, "image", appx.Spec.Image)
	// 先获取目标是否存在，已存在则不在重新创建
	deploy := &appsv1.Deployment{}
	if err := r.Get(ctx, req.NamespacedName, deploy); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return ctrl.Result{}, err
		}
		if deploy.Name == "" {
			l.Info("创建deployment:", "名字", appx.Name)
			deploy = &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      req.Name,
					Namespace: req.Namespace,
				},
				Spec: appsv1.DeploymentSpec{
					Replicas: int32Ptr(1),
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": req.Name,
						},
					},
					Template: apiv1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{
								"app": req.Name,
							},
						},
						Spec: apiv1.PodSpec{
							Containers: []apiv1.Container{
								{
									Name:  req.Name,
									Image: req.String(),
									Ports: []apiv1.ContainerPort{
										{
											Name:          "http",
											Protocol:      apiv1.ProtocolTCP,
											ContainerPort: int32(appx.Spec.Port),
										},
									},
								},
							},
						},
					},
				},
			}

			// 关联 appx和deployment
			if err := controllerutil.SetOwnerReference(appx, deploy, r.Scheme); err != nil {
				return ctrl.Result{}, err
			}
			if err := r.Create(ctx, deploy); err != nil {
				return ctrl.Result{}, err
			}
			l.Info("创建deployment成功")
		}
	}

	svc := &apiv1.Service{}
	if err := r.Get(ctx, req.NamespacedName, svc); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return ctrl.Result{}, err
		}
		if svc.Name == "" {
			l.Info("创建service:", "名字", appx.Name)
			svc = &apiv1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      req.Name,
					Namespace: req.Namespace,
				},
				Spec: apiv1.ServiceSpec{
					Selector: map[string]string{"app": req.Name},
					Ports: []apiv1.ServicePort{{
						Port:       int32(appx.Spec.Port),
						TargetPort: intstr.FromInt(appx.Spec.Port),
					},
					},
				},
			}
			// 关联 appx和deployment
			if err := controllerutil.SetOwnerReference(appx, svc, r.Scheme); err != nil {
				return ctrl.Result{}, err
			}
			if err := r.Create(ctx, svc); err != nil {
				return ctrl.Result{}, err
			}
			l.Info("创建service成功")
		}
	}
	// 目标存在则更新

	// deployment
	deploy.Spec.Template.Spec.Containers = []apiv1.Container{{
		Name:  req.Name,
		Image: appx.Spec.Image,
		Ports: []apiv1.ContainerPort{
			{
				Name:          "http",
				Protocol:      apiv1.ProtocolTCP,
				ContainerPort: int32(appx.Spec.Port),
			}},
	}}
	l.Info("更新deployment", "image:", appx.Spec.Image, "port", appx.Spec.Image)
	if err := r.Update(ctx, deploy); err != nil {
		return ctrl.Result{}, err
	}
	l.Info("deployment更新完成")

	// svc
	svc.Spec.Ports = []apiv1.ServicePort{{Port: int32(appx.Spec.Port)}}

	l.Info("更新service", "port", appx.Spec.Image)
	if err := r.Update(ctx, svc); err != nil {
		return ctrl.Result{}, err
	}
	l.Info("service更新完成")

	// 删除

	// 状态更新
	appx.Status.Workload = *deploy.Spec.Replicas
	appx.Status.Svc = fmt.Sprintf("%d", svc.Spec.Ports[0].Port)
	r.Status().Update(ctx, appx)

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AppxReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&appxv1.Appx{}).
		Complete(r)
}

func int32Ptr(i int32) *int32 { return &i }
