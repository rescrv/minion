window.MinionBuildList = React.createClass({
    render: function() {
        return <table className="minion-builds table">
            <thead>
                <tr>
                    <th>When</th>
                    <th>Target</th>
                    <th>Name</th>
                    <th></th>
                </tr>
            </thead>
            <tbody>
                {this.props.builds.map(function(build) {
                    return <BuildListItem key={build.id} build={build}/>;
                })}
            </tbody>
        </table>;
    }
});

var BuildListItem = React.createClass({
    getTimeAgo: function() {
        return jQuery.timeago(this.props.build.date);
    },
    render: function() {
        return <tr>
            <td>{this.getTimeAgo()}</td>
            <td>{this.props.build.target}</td>
            <td>{this.props.build.name}</td>
            <td><a href={'/build/' + this.props.build.id}><i className="fa fa-fw fa-link"></i></a></td>
        </tr>;
    }
});

var ProcessLog = React.createClass({
    getInitialState: function() {
        return {visible: false, log: false};
    },
    toggleVisible: function() {
        this.setState({visible: !this.state.visible, log: this.state.log});
    },
    componentDidMount: function() {
        var url = '/api/log/' + this.props.log;
        $.ajax({
            url: url,
            dataType: 'text',
            cache: true,
            success: function(data) {
                this.setState({visible: this.state.visible, log: data});
            }.bind(this),
            error: function(xhr, status, err) {
                this.setState({'error': err.toString(), 'url': url});
            }.bind(this)
        });
    },
    renderLog: function() {
        if (this.state.visible) {
            return <pre>{this.state.log}</pre>;
        } else {
            return false;
        }
    },
    render: function() {
        return <div className="minion-build-process-log">
            <div><i className="fa fa-fw fa-file-text-o"></i>&nbsp;<a onClick={this.toggleVisible}>Output Log</a></div>
            {this.renderLog()}
        </div>;
    }
});

var ProcessArtifactListItem = React.createClass({
    downloadUrl: function() {
        return '/download/' + 
            this.props.artifact.refspec + '/' +
            this.props.artifact.name;
    },
    render: function() {
        return <div>
            <i className="fa fa-fw fa-download"></i>&nbsp;
            <a href={this.downloadUrl()}>{this.props.artifact.name}</a>
        </div>
    }
});

var ProcessArtifactsList = React.createClass({
    render: function() {
        return <div className="minion-artifacts-list">
                {this.props.artifacts.map(function(artifact) {
                    return <ProcessArtifactListItem key={artifact.id} artifact={artifact}/>;
                })}
            </div>;
    }
});

var ProcessStatus = React.createClass({
    render: function() {
        if (this.props.proc.released) {
            return <i className="fa fa-fw fa-ship"></i>;
        } else if (!this.props.proc.success) {
            return <i className="fa fa-fw fa-bomb"></i>;
        } else if (this.props.proc.cached) {
            return <i className="fa fa-fw fa-recycle"></i>;
        } else if (this.props.proc.success) {
            return <i className="fa fa-fw fa-check-square"></i>;
        } else {
            return <i className="fa fa-fw fa-bomb"></i>;
        }
    }
});

var BuildProcessResultItem = React.createClass({
    render: function() {
        return <div className="panel panel-default">
            <div className="panel-heading">
                <h3 className="panel-title">
                    <ProcessStatus proc={this.props.proc} />&nbsp;
                    {this.props.proc.name}
                </h3>
            </div>
            <div className="panel-body">
                <ProcessArtifactsList artifacts={this.props.proc.artifacts}/>
                <ProcessLog log={this.props.proc.log} />
            </div>
        </div>;
    }
});

var BuildProcessResult = React.createClass({
    render: function() {
        return <div className="minion-build-processes">
            {this.props.build.processes.map(function(proc) {
                return <BuildProcessResultItem key={proc.name} proc={proc} />;
            })}
        </div>;
    }
});

window.MinionBuildProcess = React.createClass({
    render: function() {
        return <BuildProcessResult build={this.props.build} />;
    }
});
