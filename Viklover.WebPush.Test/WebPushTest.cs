using System.Text;

namespace Viklover.WebPush.Test;
/// <summary>
///      База для построения тестов
/// </summary>
public abstract class WebPushTest {
    protected static async ValueTask PrintArrayAsync(byte[] array) {
        var builder = new StringBuilder();
        builder.Append("{ ");
        for (var i = 0; i < array.Length; ++i) {
            if (i > 0) {
                builder.Append(", ");
            }
            builder.Append($"0x{array[i]:X}");
        }
        builder.Append(" }");
        var stringToPrint = builder.ToString();
        await Console.Out.WriteLineAsync(stringToPrint);
    }
    protected static string GenerateString() => Guid.NewGuid().ToString();
}
