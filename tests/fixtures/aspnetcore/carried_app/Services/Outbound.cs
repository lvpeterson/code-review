namespace CarriedApp.Services;

public class PartnerClient
{
    private readonly HttpClient _http;

    public PartnerClient(HttpClient http) { _http = http; }

    // Plain http:// partner endpoint.
    public Task<string> Fetch(string id) => _http.GetStringAsync("http://partner.example.com/items/" + id);

    public Task<string> FetchSecure(string id) => _http.GetStringAsync("https://partner.example.com/items/" + id);
}
