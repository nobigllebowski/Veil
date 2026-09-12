using Veil.Api.Auth;
using Veil.Application.Abstractions.Messaging;
using Veil.Application.Features.Devices;
using Veil.Contracts;

namespace Veil.Api.Endpoints;

internal static class DeviceEndpoints
{
    public static RouteGroupBuilder MapDeviceEndpoints(this RouteGroupBuilder api)
    {
        var group = api.MapGroup("/devices").WithTags("Devices");

        group.MapPost("/", async (RegisterDeviceRequest request, ISender sender, CancellationToken ct) =>
                (await sender.Send(new RegisterDeviceCommand(
                    request.Name,
                    request.Identity,
                    request.SignedPreKeyId,
                    request.SignedPreKey,
                    request.SignedPreKeySignature,
                    request.KemPreKeyId,
                    request.KemPreKey,
                    request.KemPreKeySignature,
                    request.OneTimePreKeys), ct))
                .ToHttp(r => Results.Created($"/api/v1/devices/{r.DeviceId}", r)))
            .Produces<DeviceRegistration>(StatusCodes.Status201Created)
            .WithSummary("Register this device's public key bundle and receive a device-bound session.");

        group.MapGet("/", async (ISender sender, CancellationToken ct) => (await sender.Send(new ListDevicesQuery(), ct)).ToOk())
            .Produces<IReadOnlyList<DeviceSummary>>();

        group.MapDelete("/{deviceId:guid}", async (Guid deviceId, ISender sender, CancellationToken ct) =>
                (await sender.Send(new RevokeDeviceCommand(deviceId), ct)).ToNoContent())
            .Produces(StatusCodes.Status204NoContent)
            .WithSummary("Revoke a device: its sessions end and peers stop encrypting to it.");

        var me = group.MapGroup("/me").RequireAuthorization(AuthPolicies.DeviceBound);

        me.MapGet("/prekeys/count", async (ISender sender, CancellationToken ct) =>
                (await sender.Send(new GetPreKeyStatusQuery(), ct)).ToHttp(count => Results.Ok(new CountResponse(count))))
            .Produces<CountResponse>()
            .WithSummary("How many one-time pre-keys remain on the server for this device.");

        me.MapPost("/prekeys", async (UploadOneTimePreKeysRequest request, ISender sender, CancellationToken ct) =>
                (await sender.Send(new UploadOneTimePreKeysCommand(request.Keys), ct)).ToHttp(count => Results.Ok(new CountResponse(count))))
            .Produces<CountResponse>()
            .WithSummary("Replenish one-time pre-keys.");

        me.MapPut("/signed-prekey", async (RotatePreKeyRequest request, ISender sender, CancellationToken ct) =>
                (await sender.Send(new RotateSignedPreKeyCommand(request.KeyId, request.PublicKey, request.Signature), ct)).ToNoContent())
            .Produces(StatusCodes.Status204NoContent);

        me.MapPut("/kem-prekey", async (RotatePreKeyRequest request, ISender sender, CancellationToken ct) =>
                (await sender.Send(new RotateKemPreKeyCommand(request.KeyId, request.PublicKey, request.Signature), ct)).ToNoContent())
            .Produces(StatusCodes.Status204NoContent);

        return api;
    }
}
