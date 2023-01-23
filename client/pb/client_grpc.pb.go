// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.6.1
// source: pb/pb.proto

package pb

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// InternalClientClient is the pb API for InternalClient service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type InternalClientClient interface {
	Query(ctx context.Context, in *InternalRequest, opts ...grpc.CallOption) (*InternalResponse, error)
}

type internalClientClient struct {
	cc grpc.ClientConnInterface
}

func NewInternalClientClient(cc grpc.ClientConnInterface) InternalClientClient {
	return &internalClientClient{cc}
}

func (c *internalClientClient) Query(ctx context.Context, in *InternalRequest, opts ...grpc.CallOption) (*InternalResponse, error) {
	out := new(InternalResponse)
	err := c.cc.Invoke(ctx, "/pb.InternalClient/Query", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// InternalClientServer is the server API for InternalClient service.
// All implementations must embed UnimplementedInternalClientServer
// for forward compatibility
type InternalClientServer interface {
	Query(context.Context, *InternalRequest) (*InternalResponse, error)
	mustEmbedUnimplementedInternalClientServer()
}

// UnimplementedInternalClientServer must be embedded to have forward compatible implementations.
type UnimplementedInternalClientServer struct {
}

func (UnimplementedInternalClientServer) Query(context.Context, *InternalRequest) (*InternalResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Query not implemented")
}
func (UnimplementedInternalClientServer) mustEmbedUnimplementedInternalClientServer() {}

// UnsafeInternalClientServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to InternalClientServer will
// result in compilation errors.
type UnsafeInternalClientServer interface {
	mustEmbedUnimplementedInternalClientServer()
}

func RegisterInternalClientServer(s grpc.ServiceRegistrar, srv InternalClientServer) {
	s.RegisterService(&InternalClient_ServiceDesc, srv)
}

func _InternalClient_Query_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(InternalRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(InternalClientServer).Query(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/pb.InternalClient/Query",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(InternalClientServer).Query(ctx, req.(*InternalRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// InternalClient_ServiceDesc is the grpc.ServiceDesc for InternalClient service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var InternalClient_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "pb.InternalClient",
	HandlerType: (*InternalClientServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Query",
			Handler:    _InternalClient_Query_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "pb/pb.proto",
}
