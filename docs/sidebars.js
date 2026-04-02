const sidebars = {
  docsSidebar: [
    'intro',
    'quickstart',
    'configuration',
    'releases',
    {
      type: 'category',
      label: '插件参考',
      items: [
        'plugin-reference/overview',
        'plugin-reference/server',
        'plugin-reference/executor',
        'plugin-reference/matcher',
        'plugin-reference/provider',
      ],
    },
    'api',
    'mikrotik-policy-routing',
    'scenarios',
    'architecture-and-design',
    'benchmarks',
  ],
};

export default sidebars;
