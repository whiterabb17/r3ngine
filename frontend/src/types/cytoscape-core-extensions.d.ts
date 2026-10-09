// `Core` methods added by the extensions registered in GraphCanvas
// (see `cytoscape-extensions.d.ts`). Only the options the app passes are declared.
import 'cytoscape';

declare module 'cytoscape' {
  /** https://github.com/iVis-at-Bilkent/cytoscape.js-expand-collapse#default-options */
  interface ExpandCollapseOptions {
    layoutBy?: LayoutOptions | null;
    fisheye?: boolean;
    animate?: boolean;
    undoable?: boolean;
    expandCollapseCuePosition?: 'top-left' | 'top-right' | 'bottom-left' | 'bottom-right';
    expandCollapseCueSize?: number;
    expandCollapseCueLineSize?: number;
    expandCueImage?: string;
    collapseCueImage?: string;
  }

  interface ExpandCollapseApi {
    collapse(eles: Collection, options?: ExpandCollapseOptions): Collection;
    expand(eles: Collection, options?: ExpandCollapseOptions): Collection;
    collapseAll(options?: ExpandCollapseOptions): Collection;
    expandAll(options?: ExpandCollapseOptions): Collection;
    isCollapsible(node: NodeSingular): boolean;
    isExpandable(node: NodeSingular): boolean;
  }

  /** https://github.com/iVis-at-Bilkent/cytoscape.js-context-menus#default-options */
  interface ContextMenuItem {
    id: string;
    content: string;
    selector?: string;
    onClickFunction?: (event: EventObject) => void;
    hasTrailingDivider?: boolean;
  }

  interface ContextMenusOptions {
    menuItems: ContextMenuItem[];
    menuItemClasses?: string[];
    contextMenuClasses?: string[];
  }

  interface Core {
    expandCollapse(options: ExpandCollapseOptions): ExpandCollapseApi;
    contextMenus(options: ContextMenusOptions): unknown;
  }
}
