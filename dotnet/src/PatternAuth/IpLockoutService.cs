namespace PatternAuth;

// In-memory per-IP login lockout. Thresholds come from PatternAuthOptions
// (default 10 failures → 15 minutes).
public class IpLockoutService
{
    private record Entry(int Failures, DateTimeOffset? LockedUntil);
    private readonly object _lock = new();
    private readonly Dictionary<string, Entry> _dict = new();
    private readonly int _maxFailures;
    private readonly TimeSpan _lockDuration;

    public IpLockoutService(PatternAuthOptions opts)
    {
        _maxFailures = opts.LockoutMaxFailures;
        _lockDuration = opts.LockoutDuration;
    }

    public (bool locked, DateTimeOffset? until, int remaining) Check(string ip)
    {
        lock (_lock)
        {
            if (!_dict.TryGetValue(ip, out var e))
                return (false, null, _maxFailures);

            if (e.LockedUntil.HasValue)
            {
                if (DateTimeOffset.UtcNow < e.LockedUntil.Value)
                    return (true, e.LockedUntil, 0);
                _dict.Remove(ip);
                return (false, null, _maxFailures);
            }

            return (false, null, _maxFailures - e.Failures);
        }
    }

    public (bool nowLocked, DateTimeOffset? until) RecordFailure(string ip)
    {
        lock (_lock)
        {
            _dict.TryGetValue(ip, out var e);

            if (e?.LockedUntil.HasValue == true && DateTimeOffset.UtcNow < e.LockedUntil.Value)
                return (true, e.LockedUntil);

            var failures = (e?.Failures ?? 0) + 1;
            if (failures >= _maxFailures)
            {
                var until = DateTimeOffset.UtcNow.Add(_lockDuration);
                _dict[ip] = new Entry(failures, until);
                return (true, until);
            }

            _dict[ip] = new Entry(failures, null);
            return (false, null);
        }
    }

    public void RecordSuccess(string ip)
    {
        lock (_lock) { _dict.Remove(ip); }
    }
}
