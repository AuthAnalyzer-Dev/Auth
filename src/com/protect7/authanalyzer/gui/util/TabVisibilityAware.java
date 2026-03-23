package com.protect7.authanalyzer.gui.util;

/**
 * 标签页可见性回调，用于在切换标签时暂停/恢复耗时操作，减轻卡顿。
 */
public interface TabVisibilityAware {
    /** 当标签变为可见时调用 */
    void onTabVisible();
    /** 当标签变为不可见时调用 */
    void onTabHidden();
}
