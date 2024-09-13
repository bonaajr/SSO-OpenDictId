namespace api_sso.Api.Helpers
{
    public static class DateTimeHelper
    {
        public static DateTime ReturnDateTimeNow()
        {
            return TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow,
                                                    TimeZoneInfo.FindSystemTimeZoneById("E. South America Standard Time"));
        }
    }
}