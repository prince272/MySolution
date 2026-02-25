namespace MySolution.WebApi.Libraries.Validator
{

    public interface IValidator
    {
        Task<ValidatorResult> ValidateAsync<TModel>(TModel model, CancellationToken ct = default);
    }
}
