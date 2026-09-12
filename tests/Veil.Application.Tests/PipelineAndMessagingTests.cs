using FluentValidation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using NSubstitute;
using Veil.Application.Abstractions.Messaging;
using Veil.Application.Abstractions.Persistence;
using Veil.Application.Abstractions.Security;
using Veil.Application.Behaviors;
using Veil.Application.Features.Messages;
using Veil.Application.Options;
using Veil.Contracts;
using Veil.Crypto.Keys;
using Veil.Domain.Common;
using Veil.Domain.Conversations;
using Veil.Domain.Devices;
using Veil.Domain.Messages;
using MsOptions = Microsoft.Extensions.Options.Options;

namespace Veil.Application.Tests;

public sealed record EchoCommand(string Text) : ICommand<Result<string>>;

internal sealed class EchoCommandValidator : AbstractValidator<EchoCommand>
{
    public EchoCommandValidator() => RuleFor(x => x.Text).NotEmpty().MaximumLength(5);
}

internal sealed class EchoCommandHandler : ICommandHandler<EchoCommand, Result<string>>
{
    public Task<Result<string>> Handle(EchoCommand request, CancellationToken cancellationToken) => Task.FromResult(Result.Success(request.Text.ToUpperInvariant()));
}

public class SenderPipelineTests
{
    private static ServiceProvider BuildProvider()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddScoped<ISender, Sender>();
        services.AddScoped(typeof(IPipelineBehavior<,>), typeof(LoggingBehavior<,>));
        services.AddScoped(typeof(IPipelineBehavior<,>), typeof(ValidationBehavior<,>));
        services.AddScoped<IValidator<EchoCommand>, EchoCommandValidator>();
        services.AddScoped<IRequestHandler<EchoCommand, Result<string>>, EchoCommandHandler>();
        return services.BuildServiceProvider();
    }

    [Fact]
    public async Task Dispatches_to_the_handler_through_behaviors()
    {
        await using var provider = BuildProvider();
        var sender = provider.GetRequiredService<ISender>();

        var result = await sender.Send(new EchoCommand("hey"));

        result.Value.ShouldBe("HEY");
    }

    [Fact]
    public async Task Validation_failure_short_circuits_with_a_typed_error()
    {
        await using var provider = BuildProvider();
        var sender = provider.GetRequiredService<ISender>();

        var result = await sender.Send(new EchoCommand("too long"));

        result.IsFailure.ShouldBeTrue();
        var error = result.Error.ShouldBeOfType<ValidationError>();
        error.Errors.ShouldHaveSingleItem().Code.ShouldBe("text");
    }

    [Fact]
    public void Result_factory_builds_failures_for_both_result_shapes()
    {
        var error = Error.Failure("x", "y");
        ResultFactory.Failure<Result>(error).Error.ShouldBe(error);
        ResultFactory.Failure<Result<int>>(error).Error.ShouldBe(error);
        Should.Throw<ValidationException>(() => ResultFactory.Failure<string>(error));
    }

    [Fact]
    public void Logging_behavior_is_constructible_with_null_logger()
    {
        var behavior = new LoggingBehavior<EchoCommand, Result<string>>(NullLogger<LoggingBehavior<EchoCommand, Result<string>>>.Instance);
        behavior.ShouldNotBeNull();
    }
}

public class SendEnvelopesCommandHandlerTests
{
    private readonly IConversationRepository _conversations = Substitute.For<IConversationRepository>();
    private readonly IDeviceRepository _devices = Substitute.For<IDeviceRepository>();
    private readonly IMessageRepository _messages = Substitute.For<IMessageRepository>();
    private readonly ICurrentUser _currentUser = Substitute.For<ICurrentUser>();
    private readonly IUnitOfWork _unitOfWork = Substitute.For<IUnitOfWork>();
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));

    private readonly Guid _alice = Guid.NewGuid();
    private readonly Guid _bob = Guid.NewGuid();
    private readonly Device _aliceDevice;
    private readonly Device _bobPhone;
    private readonly Device _bobLaptop;
    private readonly Conversation _conversation;

    public SendEnvelopesCommandHandlerTests()
    {
        _aliceDevice = NewDevice(_alice, "alice-laptop");
        _bobPhone = NewDevice(_bob, "bob-phone");
        _bobLaptop = NewDevice(_bob, "bob-laptop");
        _conversation = Conversation.CreateDirect(_alice, _bob, _time.GetUtcNow()).Value;

        _currentUser.UserId.Returns(_alice);
        _currentUser.DeviceId.Returns(_aliceDevice.Id);
        _conversations.GetByIdAsync(_conversation.Id, Arg.Any<CancellationToken>()).Returns(_conversation);
        _devices.GetActiveAsync(_alice, _aliceDevice.Id, Arg.Any<CancellationToken>()).Returns(_aliceDevice);
        _devices.ListActiveByUsersAsync(Arg.Any<IReadOnlyCollection<Guid>>(), Arg.Any<CancellationToken>())
            .Returns([_aliceDevice, _bobPhone, _bobLaptop]);
    }

    private SendEnvelopesCommandHandler Handler => new(_conversations, _devices, _messages, _currentUser, _unitOfWork, _time, MsOptions.Create(new MessagingOptions()));

    private static Device NewDevice(Guid userId, string name)
    {
        using var keys = DeviceKeyStore.Generate(oneTimePreKeyCount: 1);
        return Device.Register(userId, name, keys.ExportPublicKeys(), 0, DateTimeOffset.UtcNow).Value;
    }

    [Fact]
    public async Task Stores_one_envelope_per_addressed_device()
    {
        var command = new SendEnvelopesCommand(_conversation.Id,
        [
            new OutgoingEnvelope(_bob, _bobPhone.Id, [1, 2, 3]),
            new OutgoingEnvelope(_bob, _bobLaptop.Id, [4, 5, 6]),
        ]);

        var result = await Handler.Handle(command, CancellationToken.None);

        result.IsSuccess.ShouldBeTrue();
        result.Value.Stored.ShouldBe(2);
        _messages.Received(1).AddRange(Arg.Is<IEnumerable<MessageEnvelope>>(e => e.Count() == 2));
        await _unitOfWork.Received(1).SaveChangesAsync(Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Missing_or_stale_devices_produce_a_detailed_conflict()
    {
        var stale = Guid.NewGuid();
        var command = new SendEnvelopesCommand(_conversation.Id,
        [
            new OutgoingEnvelope(_bob, _bobPhone.Id, [1]),
            new OutgoingEnvelope(_bob, stale, [2]),
        ]);

        var result = await Handler.Handle(command, CancellationToken.None);

        var error = result.Error.ShouldBeOfType<DeviceSetMismatchError>();
        var mismatch = error.Mismatches.ShouldHaveSingleItem();
        mismatch.UserId.ShouldBe(_bob);
        mismatch.MissingDeviceIds.ShouldBe([_bobLaptop.Id]);
        mismatch.StaleDeviceIds.ShouldBe([stale]);
        _messages.DidNotReceive().AddRange(Arg.Any<IEnumerable<MessageEnvelope>>());
    }

    [Fact]
    public async Task Non_members_and_foreign_recipients_are_rejected()
    {
        var stranger = Guid.NewGuid();
        var command = new SendEnvelopesCommand(_conversation.Id, [new OutgoingEnvelope(stranger, Guid.NewGuid(), [1])]);
        (await Handler.Handle(command, CancellationToken.None)).Error.ShouldBe(MessageErrors.RecipientNotMember);

        _currentUser.UserId.Returns(stranger);
        (await Handler.Handle(command, CancellationToken.None)).Error.ShouldBe(ConversationErrors.NotFound);
    }

    [Fact]
    public async Task Requires_a_device_bound_session()
    {
        _currentUser.DeviceId.Returns((Guid?)null);
        var command = new SendEnvelopesCommand(_conversation.Id, [new OutgoingEnvelope(_bob, _bobPhone.Id, [1])]);
        (await Handler.Handle(command, CancellationToken.None)).Error.Code.ShouldBe("auth.device_required");
    }
}
