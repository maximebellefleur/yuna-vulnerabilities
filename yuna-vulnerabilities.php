<?php
/**
 * Plugin Name: Yuna Vulnerabilities
 * Plugin URI:  https://yunadesign.com
 * Description: Checks installed plugins and themes for vulnerabilities, with manual patching capabilities and an admin dashboard widget.
 * Version:     1.2.1
 * Author:      Yuna Design
 * Author URI:  https://yunadesign.com
 * Update URI:  https://github.com/yunadesign/yuna-vulnerabilities
 * License:     GPL-2.0+
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly.
}

// --- 1. CORE DATA FETCHER & HTML BUILDER ---

function yuna_get_vulnerability_data( $type, $slug, $installed_version, $item_name ) {

    // 1. Check if this specific version was manually patched by the user
    $patch_key           = $type . '_' . $slug . '_' . $installed_version;
    $patched_items       = get_option( 'yuna_patched_vulnerabilities', array() );
    $is_manually_patched = isset( $patched_items[ $patch_key ] );

    // 2. Get API Data (Cached)
    $transient_key = 'yuna_vuln_data_v6_' . md5( $type . $slug . $installed_version );
    $api_data      = get_transient( $transient_key );

    if ( false === $api_data || ! is_array( $api_data ) ) {
        $api_data = array(
            'is_vulnerable'        => false,
            'cve_id'               => '',
            'cve_link'             => '',
            'affect_text'          => '',
            'highest_vuln_version' => '0',
            'api_error'            => false,
        );

        $api_url  = 'https://www.wpvulnerability.net/' . urlencode( $type ) . '/' . urlencode( $slug ) . '/';
        $response = wp_remote_get( $api_url, array( 'timeout' => 5 ) );

        if ( is_wp_error( $response ) ) {
            $api_data['api_error'] = true;
            set_transient( $transient_key, $api_data, 5 * MINUTE_IN_SECONDS );
        } else {
            $body = wp_remote_retrieve_body( $response );
            $data = json_decode( $body, true );

            if ( isset( $data['data']['vulnerability'] ) && is_array( $data['data']['vulnerability'] ) ) {
                foreach ( $data['data']['vulnerability'] as $vuln ) {

                    $vuln_title = isset( $vuln['title'] ) ? $vuln['title'] : '';
                    if ( preg_match( '/\b(premium|pro)\b/i', $vuln_title ) && ! preg_match( '/\b(premium|pro)\b/i', $item_name ) ) {
                        continue;
                    }

                    $op_data = isset( $vuln['operator'] ) ? $vuln['operator'] : array();

                    $max_v = isset( $op_data['max_version'] ) ? $op_data['max_version'] : '0';
                    if ( $max_v !== '0' && version_compare( $max_v, $api_data['highest_vuln_version'], '>' ) ) {
                        $api_data['highest_vuln_version'] = $max_v;
                    }

                    $this_is_vulnerable = false;
                    $op                 = ( isset( $op_data['max_operator'] ) && ! empty( $op_data['max_operator'] ) ) ? $op_data['max_operator'] : '<=';

                    if ( isset( $op_data['unfixed'] ) && $op_data['unfixed'] === true ) {
                        $this_is_vulnerable   = true;
                        $current_vuln_display = 'Unfixed';
                    } elseif ( $max_v !== '0' && version_compare( $installed_version, $max_v, $op ) ) {
                        $min_v  = isset( $op_data['min_version'] ) ? $op_data['min_version'] : '0';
                        $min_op = ( isset( $op_data['min_operator'] ) && ! empty( $op_data['min_operator'] ) ) ? $op_data['min_operator'] : '>=';

                        if ( $min_v !== '0' ) {
                            if ( version_compare( $installed_version, $min_v, $min_op ) ) {
                                $this_is_vulnerable = true;
                            }
                        } else {
                            $this_is_vulnerable = true;
                        }
                        $current_vuln_display = $op . ' ' . $max_v;
                    }

                    if ( $this_is_vulnerable && ! $api_data['is_vulnerable'] ) {
                        $api_data['is_vulnerable'] = true;
                        $api_data['affect_text']   = $current_vuln_display;

                        if ( isset( $vuln['source'] ) && is_array( $vuln['source'] ) ) {
                            foreach ( $vuln['source'] as $source ) {
                                if ( isset( $source['id'] ) && strpos( $source['id'], 'CVE-' ) === 0 ) {
                                    $api_data['cve_id']   = $source['id'];
                                    $api_data['cve_link'] = 'https://www.cve.org/CVERecord?id=' . urlencode( $source['id'] );
                                    if ( isset( $source['link'] ) && empty( $api_data['cve_link'] ) ) {
                                        $api_data['cve_link'] = $source['link'];
                                    }
                                    break;
                                }
                            }
                        }
                        if ( empty( $api_data['cve_link'] ) && isset( $vuln['source'][0]['link'] ) ) {
                            $api_data['cve_link'] = $vuln['source'][0]['link'];
                            $api_data['cve_id']   = 'View Details';
                        }
                    }
                }
            }
            set_transient( $transient_key, $api_data, 12 * HOUR_IN_SECONDS );
        }
    }

    $result = $api_data;

    // 3. Build the HTML output dynamically
    if ( $api_data['api_error'] ) {
        $result['html'] = '<span style="color: #777;">API Error/Timeout</span>';
    } elseif ( $is_manually_patched ) {
        // If manually patched, override the vulnerability status so the widget ignores it
        $result['is_vulnerable'] = false;
        $result['html']          = '<span style="color: #777; font-weight: 500;">✓ Manually Patched</span>';
    } elseif ( $api_data['is_vulnerable'] ) {
        $cve_html = '';
        if ( $api_data['cve_link'] ) {
            $display_text = $api_data['cve_id'] ? $api_data['cve_id'] : 'Reference';
            $cve_html     = ' - <a href="' . esc_url( $api_data['cve_link'] ) . '" target="_blank" style="color: #dc3232; text-decoration: underline;">' . esc_html( $display_text ) . '</a>';
        }

        $status_text = '<span style="color: #dc3232; font-weight: bold;">⚠ Vulnerable (Affects ' . esc_html( $api_data['affect_text'] ) . ')' . $cve_html . '</span>';

        // Add the Manual Patch Button
        $nonce       = wp_create_nonce( 'yuna-patch-nonce' );
        $button_html = '<br><a href="#" class="yuna-manual-patch-btn" data-type="' . esc_attr( $type ) . '" data-slug="' . esc_attr( $slug ) . '" data-version="' . esc_attr( $installed_version ) . '" data-nonce="' . esc_attr( $nonce ) . '" style="display: inline-block; margin-top: 5px; font-size: 11px; text-decoration: none; padding: 2px 8px; border: 1px solid #ccc; border-radius: 3px; background: #f7f7f7; color: #555;">Mark as Patched</a>';

        $result['html'] = $status_text . $button_html;
    } else {
        if ( $api_data['highest_vuln_version'] !== '0' ) {
            $result['html'] = '<span style="color: #46b450; font-weight: 500;">✓ Clean <span style="color: #777; font-weight: normal;">(safe > ' . esc_html( $api_data['highest_vuln_version'] ) . ')</span></span>';
        } else {
            $result['html'] = '<span style="color: #46b450; font-weight: 500;">✓ Clean</span>';
        }
    }

    return $result;
}

// --- 2. AJAX HANDLER FOR MANUAL PATCHING ---

add_action( 'wp_ajax_yuna_mark_patched', 'yuna_ajax_mark_patched' );
function yuna_ajax_mark_patched() {
    check_ajax_referer( 'yuna-patch-nonce', 'nonce' );

    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( 'Permission denied' );
    }

    $type    = isset( $_POST['item_type'] ) ? sanitize_text_field( $_POST['item_type'] ) : '';
    $slug    = isset( $_POST['item_slug'] ) ? sanitize_text_field( $_POST['item_slug'] ) : '';
    $version = isset( $_POST['item_version'] ) ? sanitize_text_field( $_POST['item_version'] ) : '';

    if ( $type && $slug && $version ) {
        $patch_key               = $type . '_' . $slug . '_' . $version;
        $patched_items           = get_option( 'yuna_patched_vulnerabilities', array() );
        $patched_items[ $patch_key ] = time(); // Store the timestamp of the patch

        update_option( 'yuna_patched_vulnerabilities', $patched_items );
        wp_send_json_success();
    }
    wp_send_json_error( 'Missing data' );
}

// Inject Javascript for the Button
add_action( 'admin_footer', 'yuna_patch_button_javascript' );
function yuna_patch_button_javascript() {
    ?>
    <script type="text/javascript">
    jQuery(document).ready(function($) {
        $('.yuna-manual-patch-btn').on('click', function(e) {
            e.preventDefault();
            var btn = $(this);
            var tdContainer = btn.closest('td');

            btn.text('Patching...').css({ opacity: 0.6, pointerEvents: 'none' });

            $.post(ajaxurl, {
                action: 'yuna_mark_patched',
                nonce: btn.data('nonce'),
                item_type: btn.data('type'),
                item_slug: btn.data('slug'),
                item_version: btn.data('version')
            }, function(response) {
                if (response.success) {
                    tdContainer.html('<span style="color: #777; font-weight: 500;">✓ Manually Patched</span>');
                } else {
                    btn.text('Error').css({ opacity: 1, pointerEvents: 'auto', borderColor: 'red' });
                }
            });
        });
    });
    </script>
    <?php
}

// --- 3. PLUGIN LIST TABLE COLUMNS ---

add_filter( 'manage_plugins_columns', 'yuna_add_plugin_vulnerability_column' );
function yuna_add_plugin_vulnerability_column( $columns ) {
    $columns['yuna_vulnerability_status'] = 'Vulnerability Check';
    return $columns;
}

add_action( 'manage_plugins_custom_column', 'yuna_populate_plugin_vulnerability_column', 10, 3 );
function yuna_populate_plugin_vulnerability_column( $column_name, $plugin_file, $plugin_data ) {
    if ( 'yuna_vulnerability_status' !== $column_name ) {
        return;
    }

    $slug = dirname( $plugin_file );
    if ( '.' === $slug ) {
        $slug = basename( $plugin_file, '.php' );
    }

    $installed_version = isset( $plugin_data['Version'] ) ? $plugin_data['Version'] : '0';
    $plugin_name       = isset( $plugin_data['Name'] ) ? $plugin_data['Name'] : '';

    $vuln_data = yuna_get_vulnerability_data( 'plugin', $slug, $installed_version, $plugin_name );
    echo $vuln_data['html'];
}

// --- 4. THEME VULNERABILITY TABLE (TOP OF PLUGINS PAGE) ---

add_action( 'all_admin_notices', 'yuna_display_theme_vulnerabilities_table' );
function yuna_display_theme_vulnerabilities_table() {
    $screen = get_current_screen();

    if ( ! $screen || $screen->id !== 'plugins' ) {
        return;
    }

    $themes = wp_get_themes();

    echo '<div class="notice notice-info" style="margin-bottom: 20px; padding: 15px;">';
    echo '<h3 style="margin-top: 0;">Theme Vulnerability Check (Yuna Design)</h3>';
    echo '<table class="wp-list-table widefat fixed striped" style="border: 1px solid #ccd0d4; box-shadow: none;">';
    echo '<thead><tr>';
    echo '<th><strong>Theme Name</strong></th>';
    echo '<th><strong>Installed Version</strong></th>';
    echo '<th><strong>Vulnerability Status</strong></th>';
    echo '</tr></thead>';
    echo '<tbody>';

    foreach ( $themes as $slug => $theme ) {
        $theme_name = $theme->get( 'Name' );
        $version    = $theme->get( 'Version' );
        $vuln_data  = yuna_get_vulnerability_data( 'theme', $slug, $version, $theme_name );

        echo '<tr>';
        echo '<td><strong>' . esc_html( $theme_name ) . '</strong>' . ( $theme->errors() ? ' <em>(Broken)</em>' : '' ) . '</td>';
        echo '<td>' . esc_html( $version ) . '</td>';
        echo '<td>' . $vuln_data['html'] . '</td>';
        echo '</tr>';
    }

    echo '</tbody></table>';
    echo '</div>';
}

// --- 5. ADMIN DASHBOARD WIDGET ---

add_action( 'wp_dashboard_setup', 'yuna_add_vulnerability_dashboard_widget' );
function yuna_add_vulnerability_dashboard_widget() {
    wp_add_dashboard_widget(
        'yuna_vulnerability_dashboard_widget',
        '⚠ Vulnerability Overview (Yuna Design)',
        'yuna_render_vulnerability_dashboard_widget'
    );
}

function yuna_render_vulnerability_dashboard_widget() {
    if ( ! function_exists( 'get_plugins' ) ) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }

    $all_plugins = get_plugins();
    $all_themes  = wp_get_themes();

    $vulnerable_items = array();

    foreach ( $all_plugins as $plugin_file => $plugin_data ) {
        $slug = dirname( $plugin_file );
        if ( '.' === $slug ) {
            $slug = basename( $plugin_file, '.php' );
        }
        $version   = isset( $plugin_data['Version'] ) ? $plugin_data['Version'] : '0';
        $name      = isset( $plugin_data['Name'] ) ? $plugin_data['Name'] : $slug;
        $vuln_data = yuna_get_vulnerability_data( 'plugin', $slug, $version, $name );

        // Only show if vulnerable AND not manually patched
        if ( $vuln_data['is_vulnerable'] ) {
            $vulnerable_items[] = array(
                'type'     => 'Plugin',
                'name'     => $name,
                'url'      => admin_url( 'plugins.php' ),
                'vuln_url' => $vuln_data['cve_link'],
                'cve_id'   => $vuln_data['cve_id'] ? $vuln_data['cve_id'] : 'Threat DB',
            );
        }
    }

    foreach ( $all_themes as $slug => $theme ) {
        $name      = $theme->get( 'Name' );
        $version   = $theme->get( 'Version' );
        $vuln_data = yuna_get_vulnerability_data( 'theme', $slug, $version, $name );

        if ( $vuln_data['is_vulnerable'] ) {
            $vulnerable_items[] = array(
                'type'     => 'Theme',
                'name'     => $name,
                'url'      => admin_url( 'themes.php' ),
                'vuln_url' => $vuln_data['cve_link'],
                'cve_id'   => $vuln_data['cve_id'] ? $vuln_data['cve_id'] : 'Threat DB',
            );
        }
    }

    if ( empty( $vulnerable_items ) ) {
        echo '<p style="color: #46b450; font-weight: 500;">✓ Excellent! No unpatched vulnerabilities detected.</p>';
    } else {
        echo '<p style="color: #dc3232; font-weight: bold;">Attention Required: The following items have known security vulnerabilities.</p>';
        echo '<table class="wp-list-table widefat fixed striped" style="border: none; margin-top: 10px;">';
        echo '<thead><tr>';
        echo '<th style="padding-left: 0;"><strong>Item Name</strong></th>';
        echo '<th><strong>Type</strong></th>';
        echo '<th><strong>Reference</strong></th>';
        echo '</tr></thead>';
        echo '<tbody>';

        foreach ( $vulnerable_items as $item ) {
            echo '<tr>';
            echo '<td style="padding-left: 0;"><a href="' . esc_url( $item['url'] ) . '" style="font-weight: 600;">' . esc_html( $item['name'] ) . '</a></td>';
            echo '<td>' . esc_html( $item['type'] ) . '</td>';

            if ( ! empty( $item['vuln_url'] ) ) {
                echo '<td><a href="' . esc_url( $item['vuln_url'] ) . '" target="_blank" style="color: #dc3232; text-decoration: underline;">' . esc_html( $item['cve_id'] ) . '</a></td>';
            } else {
                echo '<td><span style="color: #777;">No Link Provided</span></td>';
            }

            echo '</tr>';
        }

        echo '</tbody></table>';
    }
}
