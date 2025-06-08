<!-- Service Control Section -->
<div class="content-box" style="margin-top: 10px;">
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-12">
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">{{ lang._('Service Control') }}</h3>
                    </div>
                    <div class="panel-body">
                        <div class="row">
                            <div class="col-md-3">
                                <strong>{{ lang._('Service Status') }}:</strong>
                                <span id="service-status" class="text-muted">{{ lang._('Checking...') }}</span>
                            </div>
                            <div class="col-md-9">
                                <button id="service-start" class="btn btn-success btn-sm" disabled>
                                    <i class="fa fa-play"></i> {{ lang._('Start') }}
                                </button>
                                <button id="service-stop" class="btn btn-danger btn-sm" disabled>
                                    <i class="fa fa-stop"></i> {{ lang._('Stop') }}
                                </button>
                                <button id="service-restart" class="btn btn-warning btn-sm" disabled>
                                    <i class="fa fa-refresh"></i> {{ lang._('Restart') }}
                                </button>
                                <button id="validate-settings" class="btn btn-info btn-sm">
                                    <i class="fa fa-check-circle"></i> {{ lang._('Validate Settings') }}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>