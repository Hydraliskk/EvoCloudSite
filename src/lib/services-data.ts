export type ServiceCategory = {
  slug: string;
  name: string;
  title: string;
  description: string;
  intro: string;
  problem: string;
  whyEvolution: string;
  seoTitle: string;
  seoDescription: string;
  icon: "monitor" | "shield" | "cloud" | "backup" | "server" | "network" | "devices";
  accent: "blue" | "emerald" | "rose" | "orange" | "violet" | "sky" | "cyan" | "fuchsia";
  summaryPoints: string[];
  solutions: string[];
  benefits: string[];
};

export const serviceCategories: ServiceCategory[] = [
  {
    slug: "services-ti-geres",
    name: "Services TI gérés",
    title: "Services TI gérés pour garder vos opérations simples et stables",
    description: "Support, maintenance et supervision proactive pour réduire les frictions au quotidien.",
    intro:
      "Evolution Cloud prend en charge la gestion courante de votre environnement TI afin que vos équipes puissent se concentrer sur leur travail plutôt que sur les problèmes techniques.",
    problem:
      "Sans accompagnement structuré, les postes, comptes utilisateurs et incidents s’accumulent et finissent par ralentir les opérations. Un service TI géré apporte une présence régulière, des priorités claires et une maintenance continue.",
    whyEvolution:
      "Nous combinons proximité, méthode et simplicité d’exécution. L’objectif est de rendre votre environnement plus prévisible, plus facile à maintenir et plus utile pour vos équipes.",
    seoTitle: "Services TI gérés pour entreprises | Evolution Cloud",
    seoDescription:
      "Support informatique, supervision proactive, gestion des postes et accompagnement MSP pour simplifier vos opérations TI.",
    icon: "monitor",
    accent: "blue",
    summaryPoints: [
      "Support informatique",
      "Gestion des postes",
      "Supervision proactive",
      "Gestion des utilisateurs",
      "Maintenance informatique",
      "Gestion des incidents"
    ],
    solutions: [
      "Support utilisateur à distance et sur site",
      "Gestion et standardisation des postes de travail",
      "Mises à jour et maintenance régulière",
      "Traitement structuré des incidents",
      "Accompagnement MSP adapté à la réalité de l’entreprise",
      "Suivi des comptes et des accès"
    ],
    benefits: [
      "Réduction du temps perdu à gérer les problèmes récurrents",
      "Vision plus claire des priorités TI",
      "Environnement plus stable pour vos équipes",
      "Accompagnement simple à suivre et à maintenir"
    ]
  },
  {
    slug: "cybersecurite",
    name: "Cybersécurité",
    title: "Cybersécurité concrète pour protéger vos utilisateurs et vos données",
    description: "Protection des postes, des accès, du réseau et des outils de collaboration.",
    intro:
      "Les menaces modernes touchent autant les PME que les grandes entreprises. Notre travail est de réduire la surface d’attaque, de mieux contrôler les accès et de vous aider à réagir vite si un incident survient.",
    problem:
      "Un compte compromis, un poste mal protégé ou une règle réseau trop ouverte peut suffire à provoquer une interruption ou une fuite de données. La cybersécurité doit donc être claire, maintenable et reliée aux vrais usages de l’entreprise.",
    whyEvolution:
      "Nous abordons la cybersécurité de façon pragmatique: d’abord la protection essentielle, ensuite la surveillance, puis l’amélioration continue selon vos risques réels.",
    seoTitle: "Cybersécurité pour entreprises | Evolution Cloud",
    seoDescription:
      "Protection des postes, sécurité Microsoft 365, MFA, pare-feu, audits et surveillance pour les entreprises.",
    icon: "shield",
    accent: "emerald",
    summaryPoints: ["Protection des postes", "EDR / antivirus", "Sécurité Microsoft 365", "MFA", "Pare-feu", "Surveillance"],
    solutions: [
      "Protection des postes et des serveurs",
      "MFA et durcissement des accès",
      "Sécurité Microsoft 365 et gestion des identités",
      "Pare-feu et protection réseau",
      "Sensibilisation au phishing",
      "Audits de sécurité et recommandations"
    ],
    benefits: [
      "Réduction du risque d’incident majeur",
      "Mise en place progressive et compréhensible",
      "Meilleure visibilité sur les accès et les alertes",
      "Protection adaptée aux PME"
    ]
  },
  {
    slug: "microsoft-365",
    name: "Microsoft 365 & Collaboration",
    title: "Microsoft 365 et collaboration pour mieux travailler ensemble",
    description: "Courriels, fichiers, réunions et collaboration dans un cadre bien géré.",
    intro:
      "Microsoft 365 est souvent au cœur du travail quotidien. Nous vous aidons à le configurer, à l’organiser et à le sécuriser pour que vos équipes puissent collaborer sans friction.",
    problem:
      "Sans structure claire, les licences, les boîtes courriel, les dossiers partagés et les accès Teams deviennent vite difficiles à gérer. Une bonne mise en place évite ces blocages et améliore la collaboration.",
    whyEvolution:
      "Nous gardons l’expérience simple pour les utilisateurs et solide pour l’administrateur. L’objectif est de rendre l’outil utile, fiable et bien encadré.",
    seoTitle: "Microsoft 365 et collaboration | Evolution Cloud",
    seoDescription:
      "Gestion Microsoft 365, Teams, SharePoint, OneDrive, migration, licences et collaboration pour entreprises.",
    icon: "cloud",
    accent: "sky",
    summaryPoints: ["Microsoft 365", "Teams", "SharePoint", "OneDrive", "Migration", "Gestion des licences"],
    solutions: [
      "Déploiement et migration Microsoft 365",
      "Gestion des utilisateurs et des licences",
      "Configuration d’Exchange Online, Teams et SharePoint",
      "Organisation des espaces collaboratifs",
      "Sécurité et accès aux données",
      "Formation et accompagnement des équipes"
    ],
    benefits: [
      "Collaboration plus fluide",
      "Mise en place plus propre et plus cohérente",
      "Réduction des erreurs de configuration",
      "Meilleur contrôle des accès et des licences"
    ]
  },
  {
    slug: "materiel-licences",
    name: "Matériel informatique & licences",
    title: "Matériel informatique et licences pour garder vos équipes bien équipées",
    description: "Ordinateurs, écrans, accessoires, logiciels et équipements réseau pour soutenir vos opérations.",
    intro:
      "Evolution Cloud vous aide à choisir, fournir et standardiser le matériel et les licences qui soutiennent réellement vos besoins d’affaires, sans alourdir votre environnement.",
    problem:
      "Quand le parc informatique est hétérogène ou mal renouvelé, les coûts de support montent et les équipes perdent du temps. Des équipements cohérents et des licences bien gérées simplifient l’exploitation au quotidien.",
    whyEvolution:
      "Nous privilégions des achats utiles, des configurations claires et des choix cohérents avec votre réalité. L’objectif est de fournir du matériel fiable, facile à administrer et bien aligné avec vos besoins.",
    seoTitle: "Matériel informatique et licences | Evolution Cloud",
    seoDescription:
      "Ordinateurs, écrans, accessoires, logiciels, licences et équipements réseau pour entreprises.",
    icon: "devices",
    accent: "orange",
    summaryPoints: ["Ordinateurs", "Écrans", "Accessoires", "Logiciels", "Licences", "Équipements réseau"],
    solutions: [
      "Fourniture d’ordinateurs et d’accessoires",
      "Écrans, stations d’accueil et périphériques",
      "Licences logicielles et abonnements",
      "Équipements réseau et postes de travail",
      "Standardisation du parc informatique",
      "Aide au renouvellement et au déploiement"
    ],
    benefits: [
      "Parc plus cohérent et plus simple à soutenir",
      "Achat plus clair pour les équipes",
      "Meilleure compatibilité entre les postes et les outils",
      "Gestion plus efficace des licences et des remplacements"
    ]
  },
  {
    slug: "sauvegarde-continuite",
    name: "Sauvegarde & Continuité",
    title: "Sauvegarde et continuité pour protéger votre capacité à repartir vite",
    description: "Prévenir la perte de données et assurer la reprise de vos opérations.",
    intro:
      "La sauvegarde n’est pas seulement une copie de fichiers. C’est un mécanisme de protection qui vous permet de récupérer rapidement après une erreur, un bris ou un incident de sécurité.",
    problem:
      "Sans stratégie claire, une perte de données ou un arrêt imprévu peut coûter beaucoup de temps, d’argent et de confiance. Il faut donc penser à la sauvegarde, à la restauration et à la reprise avant que le problème arrive.",
    whyEvolution:
      "Nous bâtissons des stratégies de sauvegarde simples à comprendre et réellement utiles au moment critique. La restauration doit être testée, documentée et disponible.",
    seoTitle: "Sauvegarde et continuité d’entreprise | Evolution Cloud",
    seoDescription:
      "Sauvegarde des postes, serveurs et Microsoft 365, stratégie 3-2-1, restauration et reprise après sinistre.",
    icon: "backup",
    accent: "rose",
    summaryPoints: ["Sauvegarde des postes", "Sauvegarde des serveurs", "Sauvegarde Microsoft 365", "NAS", "Stratégie 3-2-1", "Reprise après sinistre"],
    solutions: [
      "Sauvegarde locale et cloud",
      "Protection des postes, serveurs et données cloud",
      "Stratégie 3-2-1 adaptée à l’entreprise",
      "Restauration documentée et testée",
      "Solution de continuité et de reprise",
      "Encadrement des sauvegardes Microsoft 365"
    ],
    benefits: [
      "Réduction de l’impact d’un incident",
      "Restauration plus simple et plus rapide",
      "Protection des données essentielles",
      "Approche claire pour les décideurs"
    ]
  },
  {
    slug: "cloud-infrastructure",
    name: "Cloud & Infrastructure",
    title: "Cloud et infrastructure pour moderniser votre environnement TI",
    description: "Serveurs, virtualisation, hébergement et modernisation des fondations TI.",
    intro:
      "Le cloud et l’infrastructure doivent soutenir l’entreprise, pas la ralentir. Nous aidons à choisir, structurer et faire évoluer une base technique fiable et cohérente.",
    problem:
      "Quand l’infrastructure est vieillissante ou mal assemblée, elle devient plus coûteuse à maintenir et plus difficile à faire évoluer. Une architecture plus moderne aide à réduire cette pression.",
    whyEvolution:
      "Nous aimons les infrastructures lisibles, documentées et adaptées à la croissance. Le but est d’éviter les empilements inutiles et de garder une bonne stabilité dans le temps.",
    seoTitle: "Cloud et infrastructure TI | Evolution Cloud",
    seoDescription:
      "Serveurs, virtualisation, hébergement, migration et modernisation d’infrastructure pour entreprises.",
    icon: "server",
    accent: "violet",
    summaryPoints: ["Serveurs", "Virtualisation", "Hébergement", "Stockage", "Migration", "Infrastructure hybride"],
    solutions: [
      "Modernisation des serveurs et des environnements",
      "Virtualisation et consolidation",
      "Migration vers des fondations plus flexibles",
      "Gestion du stockage et des ressources",
      "Architecture hybride selon les besoins",
      "Accompagnement pour faire évoluer l’infrastructure"
    ],
    benefits: [
      "Base technique plus robuste",
      "Meilleure capacité d’évolution",
      "Ressources mieux utilisées",
      "Planification plus simple pour l’entreprise"
    ]
  },
  {
    slug: "reseau-telecommunications",
    name: "Réseau & Télécommunications",
    title: "Réseau et télécommunications pour garder les équipes connectées",
    description: "Wi-Fi, pare-feu, VPN, téléphonie IP et accès distant sécurisé.",
    intro:
      "Un réseau bien pensé est invisible quand tout fonctionne, mais critique quand il faut dépanner, sécuriser ou faire croître l’entreprise. Nous construisons des environnements réseau plus propres et plus fiables.",
    problem:
      "Des réseaux mal segmentés, un Wi-Fi inégal ou une téléphonie mal intégrée peuvent nuire à la productivité et à la sécurité. Il faut une base réseau simple, stable et bien documentée.",
    whyEvolution:
      "Nous privilégions des réseaux pratiques à exploiter et à maintenir. Le résultat recherché: moins d’interruptions, moins de confusion et plus de contrôle.",
    seoTitle: "Réseau et télécommunications pour entreprises | Evolution Cloud",
    seoDescription:
      "Réseaux d’entreprise, Wi-Fi, VPN, pare-feu, téléphonie IP et accès distant sécurisé pour entreprises.",
    icon: "network",
    accent: "cyan",
    summaryPoints: ["Réseaux d’entreprise", "Wi-Fi", "Pare-feu", "VPN", "Téléphonie IP", "Accès distant sécurisé"],
    solutions: [
      "Conception et gestion du réseau d’entreprise",
      "Configuration Wi-Fi et segmentation",
      "Pare-feu, VPN et accès distant",
      "Téléphonie IP et communications unifiées",
      "Maintenance et documentation réseau",
      "Optimisation de la connectivité des sites"
    ],
    benefits: [
      "Connexions plus stables",
      "Meilleur contrôle des accès",
      "Réseau plus facile à faire évoluer",
      "Support plus efficace quand un problème survient"
    ]
  },
  {
    slug: "loi-25",
    name: "Loi 25 & Conformité",
    title: "Loi 25 et conformité pour mieux encadrer vos pratiques numériques",
    description: "Aide à structurer les mesures, les accès et la documentation liés aux renseignements personnels.",
    intro:
      "Evolution Cloud vous aide à mieux organiser les aspects technologiques liés à la protection des renseignements personnels, à la gestion des accès et à la documentation utile à vos pratiques internes.",
    problem:
      "Quand les outils, les accès et les processus sont dispersés, il devient plus difficile de démontrer un encadrement cohérent des renseignements personnels. Une approche simple et documentée réduit ce risque.",
    whyEvolution:
      "Nous travaillons de façon pragmatique: faire le tri, clarifier les responsabilités techniques et rendre les pratiques plus faciles à maintenir dans le temps.",
    seoTitle: "Loi 25 et conformité TI | Evolution Cloud",
    seoDescription:
      "Aide à structurer les mesures techniques, les accès, la documentation et les pratiques liées à la conformité.",
    icon: "shield",
    accent: "fuchsia",
    summaryPoints: ["Mesures techniques", "Gestion des accès", "Documentation", "Rétention", "Processus internes", "Conformité"],
    solutions: [
      "Revue des outils et des flux de données",
      "Encadrement des accès et des privilèges",
      "Appui à la documentation technique utile",
      "Soutien aux mesures de protection et de rétention",
      "Recommandations pragmatiques pour les équipes",
      "Alignement avec les pratiques de cybersécurité"
    ],
    benefits: [
      "Pratiques plus claires à appliquer",
      "Meilleur contrôle des accès et des outils",
      "Documentation plus facile à maintenir",
      "Approche technologique mieux structurée"
    ]
  }
];

export const servicesOverview = [
  {
    slug: "services-ti-geres",
    title: "Services TI gérés",
    description: "Support, maintenance et supervision proactive pour garder vos opérations stables.",
    icon: "monitor",
    points: ["Support informatique", "Supervision proactive", "Gestion des incidents"]
  },
  {
    slug: "microsoft-365",
    title: "Microsoft 365 & Collaboration",
    description: "Courriel, Teams et partage de fichiers bien structurés.",
    icon: "cloud",
    points: ["Teams", "SharePoint", "Licences"]
  },
  {
    slug: "materiel-licences",
    title: "Matériel informatique & licences",
    description: "Ordinateurs, écrans, accessoires et licences pour garder vos équipes bien outillées.",
    icon: "devices",
    points: ["Ordinateurs", "Écrans", "Logiciels"]
  },
  {
    slug: "cybersecurite",
    title: "Cybersécurité",
    description: "Protection concrète des postes, des accès et du réseau.",
    icon: "shield",
    points: ["MFA", "EDR", "Audits"]
  },
  {
    slug: "sauvegarde-continuite",
    title: "Sauvegarde & Continuité",
    description: "Préparez la restauration et la reprise avant le problème.",
    icon: "backup",
    points: ["3-2-1", "NAS", "Restauration"]
  },
  {
    slug: "cloud-infrastructure",
    title: "Cloud & Infrastructure",
    description: "Serveurs, virtualisation et modernisation des fondations TI.",
    icon: "server",
    points: ["Virtualisation", "Migration", "Hybride"]
  },
  {
    slug: "reseau-telecommunications",
    title: "Réseau & Télécommunications",
    description: "Wi-Fi, VPN, téléphonie IP et connectivité sécurisée.",
    icon: "network",
    points: ["Wi-Fi", "VPN", "Téléphonie IP"]
  },
  {
    slug: "loi-25",
    title: "Loi 25 & Conformité",
    description: "Encadrement technique et documentation pour mieux structurer vos pratiques.",
    icon: "shield",
    points: ["Accès", "Documentation", "Rétention"]
  }
];

export const servicesNavLinks = [
  { href: "/services/", label: "Tous nos services" },
  { href: "/services/services-ti-geres/", label: "Services TI gérés" },
  { href: "/services/microsoft-365/", label: "Microsoft 365 & Collaboration" },
  { href: "/services/materiel-licences/", label: "Matériel informatique & licences" },
  { href: "/services/cybersecurite/", label: "Cybersécurité" },
  { href: "/services/sauvegarde-continuite/", label: "Sauvegarde & Continuité" },
  { href: "/services/cloud-infrastructure/", label: "Cloud & Infrastructure" },
  { href: "/services/reseau-telecommunications/", label: "Réseau & Télécommunications" },
  { href: "/services/loi-25/", label: "Loi 25 & Conformité" }
];
