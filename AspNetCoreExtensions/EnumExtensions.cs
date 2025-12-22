using System.ComponentModel.DataAnnotations;
using System.Reflection;
using System.Text.RegularExpressions;

namespace AspNetCoreExtensions;

public static partial class EnumExtensions
{
    [GeneratedRegex("([^^])([A-Z])")]
    private static partial Regex PascalCaseToSpaces();

    extension(Enum enumValue)
    {
        /// <summary>
        ///     A generic extension method that aids in reflecting
        ///     and retrieving any attribute that is applied to an `Enum`.
        /// </summary>
        private TAttribute? GetAttribute<TAttribute>()
            where TAttribute : Attribute
        {
            return enumValue.GetType()
                .GetMember(enumValue.ToString())
                .First()
                .GetCustomAttribute<TAttribute>();
        }

        public string GetDisplayName()
        {
            var displayAttr = enumValue.GetAttribute<DisplayAttribute>();
            return displayAttr?.Name ??
                   throw new ArgumentNullException(nameof(enumValue), "Enum does not have a display name.");
        }

        public bool TryGetDisplayName(out string? value)
        {
            var displayAttr = enumValue.GetAttribute<DisplayAttribute>();
            value = displayAttr?.Name;
            return value is not null;
        }

        public string GetDisplayDescription()
        {
            var displayAttr = enumValue.GetAttribute<DisplayAttribute>();
            return displayAttr?.Description ??
                   throw new ArgumentNullException(nameof(enumValue), "Enum does not have a display description.");
        }

        public bool TryGetDisplayDescription(out string? value)
        {
            var displayAttr = enumValue.GetAttribute<DisplayAttribute>();
            value = displayAttr?.Description;
            return value is not null;
        }

        public string GetShortName()
        {
            var displayAttr = enumValue.GetAttribute<DisplayAttribute>();
            return displayAttr?.ShortName ??
                   throw new ArgumentNullException(nameof(enumValue), "Enum does not have a short name.");
        }

        public bool TryGetShortName(out string? value)
        {
            var displayAttr = enumValue.GetAttribute<DisplayAttribute>();
            value = displayAttr?.ShortName;
            return value is not null;
        }

        public string GetSpaceSeparatedDisplayString()
        {
            var val = enumValue.TryGetDisplayName(out var displayName)
                ? displayName
                : enumValue.ToString();

            if (val is null)
            {
                throw new ArgumentNullException(nameof(enumValue));
            }

            return PascalCaseToSpaces().Replace(val, "$1 $2"
            );
        }
    }
}