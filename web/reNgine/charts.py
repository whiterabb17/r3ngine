import base64
import colorsys
import logging

logger = logging.getLogger(__name__)

import plotly.io as pio
import plotly.graph_objs as go
from plotly.io import to_image

# Kaleido's Chromium subprocess refuses to start as root (common in Docker)
# without the --no-sandbox flag, which causes to_image() to hang indefinitely.
pio.kaleido.scope.chromium_args = ("--no-sandbox",)
from django.db.models import Count
from reNgine.definitions import NUCLEI_SEVERITY_MAP

from startScan.models import *



"""
    This file is used to generate the charts for the pdf report.
"""

def generate_subdomain_chart_by_http_status(subdomains):
    """
    Generates a donut chart using plotly for the subdomains based on the http status.
    Includes label, count, and percentage inside the chart segments and in the legend.
    Args:
        subdomains: QuerySet of subdomains.
    Returns:
        Image as base64 encoded string.
    """
    http_statuses = (
        subdomains
        .exclude(http_status=0)
        .values('http_status')
        .annotate(count=Count('http_status'))
        .order_by('-count')
    )
    http_status_count = [{'http_status': entry['http_status'], 'count': entry['count']} for entry in http_statuses]

    total = sum(entry['count'] for entry in http_status_count)
    
    labels = [str(entry['http_status']) for entry in http_status_count]
    sizes = [entry['count'] for entry in http_status_count]
    colors = [get_color_by_http_status(entry['http_status']) for entry in http_status_count]

    text = [f"{label}<br>{size}<br>({size/total:.1%})" for label, size in zip(labels, sizes)]

    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=sizes,
        marker=dict(colors=colors),
        hole=0.4,
        textinfo="text",
        text=text,
        textposition="inside",
        textfont=dict(size=10),
        hoverinfo="label+percent+value"
    )])
    
    fig.update_layout(
        title_text="",
        annotations=[dict(text='HTTP Status', x=0.5, y=0.5, font_size=14, showarrow=False)],
        showlegend=True,
        margin=dict(t=60, b=60, l=60, r=60),
        width=700,
        height=700,
        legend=dict(
            font=dict(size=18),
            orientation="v",
            yanchor="middle",
            y=0.5,
            xanchor="left",
            x=1.05
        ),
    )

    img_bytes = to_image(fig, format="png")
    img_base64 = base64.b64encode(img_bytes).decode('utf-8')
    return img_base64



def get_color_by_severity(severity_int):
    """
    Returns a color based on the severity level using a modern color scheme.
    """
    color_map = {
        4: '#FF4D6A',
        3: '#FF9F43',
        2: '#FFCA3A',
        1: '#4ADE80',
        0: '#4ECDC4',
        -1: '#A8A9AD',
    }
    return color_map.get(severity_int, '#A8A9AD')  # Default to gray if severity is unknown

def generate_vulnerability_chart_by_severity(vulnerabilities):
    """
    Generates a donut chart using plotly for the vulnerabilities based on the severity.
    Args:
        vulnerabilities: QuerySet of Vulnerability objects.
    Returns:
        Image as base64 encoded string.
    """
    severity_counts = (
        vulnerabilities
        .values('severity')
        .annotate(count=Count('severity'))
        .order_by('-severity')
    )
    
    total = sum(entry['count'] for entry in severity_counts)
    
    labels = [NUCLEI_REVERSE_SEVERITY_MAP[entry['severity']].capitalize() for entry in severity_counts]
    values = [entry['count'] for entry in severity_counts]
    colors = [get_color_by_severity(entry['severity']) for entry in severity_counts]
    
    text = [f"{label}<br>{value}<br>({value/total:.1%})" for label, value in zip(labels, values)]

    fig = go.Figure(data=[go.Pie(
        labels=labels, 
        values=values,
        marker=dict(colors=colors),
        hole=0.4,
        textinfo="text",
        text=text,
        textposition="inside",
        textfont=dict(size=12),
        hoverinfo="label+percent+value",
    )])
    
    fig.update_layout(
        title_text="",
        annotations=[dict(text='Severity', x=0.5, y=0.5, font_size=14, showarrow=False)],
        showlegend=True,
        margin=dict(t=60, b=60, l=60, r=60),
        width=700,
        height=700,
        legend=dict(
            font=dict(size=18),
            orientation="v",
            yanchor="middle",
            y=0.5,
            xanchor="left",
            x=1.05
        ),
    )


    img_bytes = to_image(fig, format="png")
    img_base64 = base64.b64encode(img_bytes).decode('utf-8')
    return img_base64



def generate_color(base_color, offset):
    r, g, b = int(base_color[1:3], 16), int(base_color[3:5], 16), int(base_color[5:7], 16)
    factor = 1 + (offset * 0.03)
    r, g, b = [min(255, int(c * factor)) for c in (r, g, b)]
    return f"#{r:02x}{g:02x}{b:02x}"


def get_color_by_http_status(http_status):
    """
        Returns the color based on the http status.
        Args:
            http_status: HTTP status code.
        Returns:
            Color code.
    """

    status = int(http_status)
    
    colors = {
        200: "#36a2eb",
        300: "#4bc0c0",
        400: "#ff6384",
        401: "#ff9f40",
        403: "#f27474",
        404: "#ffa1b5",
        429: "#bf7bff",
        500: "#9966ff",
        502: "#8a4fff",
        503: "#c39bd3",
    }


    if status in colors:
        return colors[status]
    elif 200 <= status < 300:
        return generate_color(colors[200], status - 200)
    elif 300 <= status < 400:
        return generate_color(colors[300], status - 300)
    elif 400 <= status < 500:
        return generate_color(colors[400], status - 400)
    elif 500 <= status < 600:
        return generate_color(colors[500], status - 500)
    else:
        return "#c9cbcf"


def generate_attack_surface_map(graph_data):
    """
    Generates a static network graph using plotly from Cytoscape JSON data.
    Args:
        graph_data: Dictionary with 'nodes' and 'edges' (Cytoscape format).
    Returns:
        Image as base64 encoded string.
    """
    import math
    nodes = graph_data.get('nodes', [])
    edges = graph_data.get('edges', [])
    
    if not nodes:
        return None

    # Compute positions (Circular Layout for simplicity and no dependencies)
    n = len(nodes)
    pos = {}
    for i, node in enumerate(nodes):
        angle = 2 * math.pi * i / n if n > 0 else 0
        # Radius can be varied for a bit more spread if needed
        pos[node['data']['id']] = (math.cos(angle), math.sin(angle))
        
    edge_x = []
    edge_y = []
    for edge in edges:
        source = edge['data'].get('source')
        target = edge['data'].get('target')
        if source in pos and target in pos:
            x0, y0 = pos[source]
            x1, y1 = pos[target]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.5, color='rgba(148, 163, 184, 0.3)'),
        hoverinfo='none',
        mode='lines')

    node_x = []
    node_y = []
    node_color = []
    node_text = []
    for node in nodes:
        x, y = pos[node['data']['id']]
        node_x.append(x)
        node_y.append(y)
        node_color.append(node['data'].get('color', '#94a3b8'))
        node_text.append(node['data'].get('label', ''))

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers',
        text=node_text,
        hoverinfo='text',
        marker=dict(
            showscale=False,
            color=node_color,
            size=12,
            line=dict(width=1, color='white')))

    fig = go.Figure(data=[edge_trace, node_trace],
                 layout=go.Layout(
                    paper_bgcolor='#0f172a',
                    plot_bgcolor='#0f172a',
                    showlegend=False,
                    hovermode='closest',
                    margin=dict(b=20, l=5, r=5, t=40),
                    xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                    yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                    width=1000,
                    height=800
                ))
    
    try:
        img_bytes = to_image(fig, format="png")
        img_base64 = base64.b64encode(img_bytes).decode('utf-8')
        return img_base64
    except Exception as e:
        logger.error("Error generating graph image: %s", e)
        return None


def generate_stress_latency_chart(results):
    """
    Generates a bar chart for stress test latency (Avg, P95, P99).
    """
    labels = []
    avg_latency = []
    p95_latency = []
    p99_latency = []
    
    for res in results:
        labels.append(f"{res.tool_used}")
        avg_latency.append(res.avg_latency_ms)
        p95_latency.append(res.p95_latency_ms)
        p99_latency.append(res.p99_latency_ms)

    fig = go.Figure(data=[
        go.Bar(name='Average', x=labels, y=avg_latency, marker_color='#4ECDC4'),
        go.Bar(name='P95', x=labels, y=p95_latency, marker_color='#FF9F43'),
        go.Bar(name='P99', x=labels, y=p99_latency, marker_color='#FF4D6A')
    ])

    fig.update_layout(
        barmode='group',
        title="Latency Analysis (ms)",
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(size=14),
        margin=dict(t=60, b=60, l=60, r=60),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
    )

    img_bytes = to_image(fig, format="png")
    return base64.b64encode(img_bytes).decode('utf-8')


def generate_stress_success_rate_chart(results):
    """
    Generates a donut chart for stress test success vs failure.
    """
    total_success = sum(r.successful_requests for r in results)
    total_failed = sum(r.failed_requests for r in results)
    
    labels = ['Success', 'Failed']
    values = [total_success, total_failed]
    colors = ['#4ADE80', '#FF4D6A']

    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        marker=dict(colors=colors),
        hole=0.4,
        textinfo='percent+label',
        textfont=dict(size=14)
    )])

    fig.update_layout(
        title="Overall Success Rate",
        showlegend=True,
        margin=dict(t=60, b=60, l=60, r=60),
        width=600,
        height=600
    )

    img_bytes = to_image(fig, format="png")
    return base64.b64encode(img_bytes).decode('utf-8')


def generate_stress_latency_distribution_chart(stress_result):
    """
    Generates a bar chart for stress test latency distribution (all percentiles).
    Args:
        stress_result: StressTestResult object.
    Returns:
        Image as base64 encoded string.
    """
    labels = ['P50', 'P75', 'P90', 'P95', 'P99', 'P999', 'Avg']
    values = [
        stress_result.p50_latency_ms,
        stress_result.p75_latency_ms,
        stress_result.p90_latency_ms,
        stress_result.p95_latency_ms,
        stress_result.p99_latency_ms,
        stress_result.p999_latency_ms,
        stress_result.avg_latency_ms,
    ]

    colors = ['#4ECDC4', '#4BC0C0', '#45B7B1', '#FF9F43', '#FF6B35', '#FF4D6A', '#6C5CE7']

    fig = go.Figure(data=[
        go.Bar(x=labels, y=values, marker_color=colors, text=values, textposition='auto')
    ])

    fig.update_layout(
        title="Latency Distribution (ms)",
        yaxis_title="Latency (ms)",
        xaxis_title="Percentile",
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(size=12),
        margin=dict(t=60, b=60, l=60, r=60),
        width=700,
        height=400,
        showlegend=False
    )

    img_bytes = to_image(fig, format="png")
    return base64.b64encode(img_bytes).decode('utf-8')


def generate_stress_response_code_chart(response_code_distribution):
    """
    Generates a pie chart for stress test response code distribution.
    Args:
        response_code_distribution: Dictionary of {code: count}.
    Returns:
        Image as base64 encoded string.
    """
    if not response_code_distribution:
        return None

    codes = []
    counts = []
    colors = []

    for code, count in sorted(response_code_distribution.items(), key=lambda x: x[1], reverse=True):
        codes.append(str(code))
        counts.append(count)
        colors.append(get_color_by_http_status(code))

    total = sum(counts)
    text = [f"{code}<br>{count}<br>({count/total:.1%})" for code, count in zip(codes, counts)]

    fig = go.Figure(data=[go.Pie(
        labels=codes,
        values=counts,
        marker=dict(colors=colors),
        textinfo="text",
        text=text,
        textposition="inside",
        textfont=dict(size=10),
        hoverinfo="label+percent+value"
    )])

    fig.update_layout(
        title="Response Code Distribution",
        showlegend=True,
        margin=dict(t=60, b=60, l=60, r=60),
        width=700,
        height=700,
        legend=dict(
            font=dict(size=12),
            orientation="v",
            yanchor="middle",
            y=0.5,
            xanchor="left",
            x=1.05
        ),
    )

    img_bytes = to_image(fig, format="png")
    return base64.b64encode(img_bytes).decode('utf-8')


def generate_stress_error_breakdown_chart(error_breakdown):
    """
    Generates a bar chart for stress test error type breakdown.
    Args:
        error_breakdown: Dictionary of {error_type: count}.
    Returns:
        Image as base64 encoded string.
    """
    if not error_breakdown:
        return None

    error_types = list(error_breakdown.keys())
    counts = list(error_breakdown.values())

    color_map = {
        'timeout': '#FF4D6A',
        'connection_refused': '#FF9F43',
        'connection_reset': '#FFCA3A',
        'tls_error': '#FF6B35',
        'http_error': '#6C5CE7',
    }

    colors = [color_map.get(error_type, '#4ECDC4') for error_type in error_types]

    fig = go.Figure(data=[
        go.Bar(
            x=error_types,
            y=counts,
            marker_color=colors,
            text=counts,
            textposition='auto'
        )
    ])

    fig.update_layout(
        title="Error Type Breakdown",
        yaxis_title="Count",
        xaxis_title="Error Type",
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(size=12),
        margin=dict(t=60, b=60, l=60, r=60),
        width=700,
        height=400,
        showlegend=False
    )

    img_bytes = to_image(fig, format="png")
    return base64.b64encode(img_bytes).decode('utf-8')


def generate_stress_endpoint_heatmap(endpoints_tested, response_code_distribution):
    """
    Generates a heatmap visualization for endpoints and response codes.
    Args:
        endpoints_tested: List of endpoint URLs.
        response_code_distribution: Dictionary of {code: count}.
    Returns:
        Image as base64 encoded string.
    """
    if not endpoints_tested or not response_code_distribution:
        return None

    # Limit to first 10 endpoints for readability
    endpoint_list = endpoints_tested[:10] if isinstance(endpoints_tested, list) else list(endpoints_tested)[:10]
    endpoint_labels = [str(ep) if isinstance(ep, str) else ep.get('url', str(ep)) for ep in endpoint_list]

    # Status code categories
    status_2xx = sum(v for k, v in response_code_distribution.items() if 200 <= int(k) < 300)
    status_3xx = sum(v for k, v in response_code_distribution.items() if 300 <= int(k) < 400)
    status_4xx = sum(v for k, v in response_code_distribution.items() if 400 <= int(k) < 500)
    status_5xx = sum(v for k, v in response_code_distribution.items() if 500 <= int(k) < 600)

    # Create simple heatmap data (endpoints vs status categories)
    z_data = []
    for i in range(len(endpoint_list)):
        z_data.append([status_2xx, status_3xx, status_4xx, status_5xx])

    fig = go.Figure(data=go.Heatmap(
        z=z_data,
        x=['2xx Success', '3xx Redirect', '4xx Client Error', '5xx Server Error'],
        y=endpoint_labels,
        colorscale='RdYlGn_r',
        text=z_data,
        texttemplate='%{text}',
        textfont={"size": 10},
    ))

    fig.update_layout(
        title="Response Code Distribution by Endpoint",
        yaxis_title="Endpoint",
        xaxis_title="Status Code Category",
        margin=dict(t=60, b=60, l=200, r=60),
        width=700,
        height=400 + len(endpoint_list) * 20,
    )

    img_bytes = to_image(fig, format="png")
    return base64.b64encode(img_bytes).decode('utf-8')