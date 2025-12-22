using System.Collections;

namespace AspNetCoreExtensions;

public static class ListExtension
{
    extension(IList list)
    {
        public void AddIfNotNull<T>(T? obj)
        {
            if (obj is not null)
            {
                list.Add(obj);
            }
        }
    }
}