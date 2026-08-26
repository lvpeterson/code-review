from languages.ruby.rails_analyzer import RailsAnalyzer


def _write(tmp_path, rel_path, content):
    path = tmp_path / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_named_route_with_to_target(tmp_path):
    _write(
        tmp_path,
        "config/routes.rb",
        "Rails.application.routes.draw do\n"
        "  get 'status', to: 'status#show'\n"
        "end\n",
    )
    routes = RailsAnalyzer(tmp_path).find_routes()
    assert len(routes) == 1
    assert routes[0].path == "/status"
    assert routes[0].handler_name == "status#show"


def test_resources_expands_to_seven_restful_routes(tmp_path):
    _write(
        tmp_path,
        "config/routes.rb",
        "Rails.application.routes.draw do\n"
        "  resources :orders\n"
        "end\n",
    )
    routes = RailsAnalyzer(tmp_path).find_routes()
    assert len(routes) == 7
    by_action = {r.handler_name: (r.methods[0], r.path) for r in routes}
    assert by_action["orders#index"] == ("GET", "/orders")
    assert by_action["orders#show"] == ("GET", "/orders/:id")
    assert by_action["orders#create"] == ("POST", "/orders")
    assert by_action["orders#update"] == ("PATCH", "/orders/:id")
    assert by_action["orders#destroy"] == ("DELETE", "/orders/:id")


def test_namespace_prefixes_nested_resources(tmp_path):
    _write(
        tmp_path,
        "config/routes.rb",
        "Rails.application.routes.draw do\n"
        "  namespace :api do\n"
        "    resources :orders\n"
        "  end\n"
        "end\n",
    )
    routes = RailsAnalyzer(tmp_path).find_routes()
    paths = {r.path for r in routes}
    assert "/api/orders" in paths
    assert "/api/orders/:id" in paths


def test_global_before_action_auth_is_detected(tmp_path):
    _write(
        tmp_path,
        "config/routes.rb",
        "Rails.application.routes.draw do\n"
        "  resources :orders\n"
        "end\n",
    )
    _write(
        tmp_path,
        "app/controllers/application_controller.rb",
        "class ApplicationController < ActionController::Base\n"
        "  before_action :authenticate_user!\n"
        "end\n",
    )
    result = RailsAnalyzer(tmp_path).analyze()
    assert result.global_auth_source is not None
    assert "application_controller.rb" in result.global_auth_source[0]


def test_no_application_controller_means_no_global_note(tmp_path):
    _write(
        tmp_path,
        "config/routes.rb",
        "Rails.application.routes.draw do\n  resources :orders\nend\n",
    )
    result = RailsAnalyzer(tmp_path).analyze()
    assert result.global_auth_source is None
