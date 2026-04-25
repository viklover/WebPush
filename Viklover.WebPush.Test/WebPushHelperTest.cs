using Viklover.WebPush.Process;

namespace Viklover.WebPush.Test;

public class WebPushHelperTest {
    [TestCase("aGVsbG8gd29ybGQ")]
    [Test(Description = "Тест на декодирование и кодирование base64url")]
    public void DecodeAndEncodeTest(string base64Input) {
        var decodedInput = WebPushHelper.DecodeBase64(base64Input);
        var encodedInput = WebPushHelper.EncodeBase64(decodedInput);
        Assert.That(encodedInput, Is.EqualTo(base64Input));
    }
}
