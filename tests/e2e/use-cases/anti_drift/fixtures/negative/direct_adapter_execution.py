def test_bad_direct_adapter_execution(adapter, request):
    # Scenario code must not bypass the gateway/verifier path.
    return adapter.execute(request)
