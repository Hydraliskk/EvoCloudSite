export type VideoItem = {
  title: string;
  description: string;
  youtubeId: string;
  duration: string;
};

export type VideoCategory = {
  slug: string;
  title: string;
  description: string;
  videos: VideoItem[];
};

export const youtubeChannelUrl = "https://www.youtube.com/@EvolutionCloud-k6f";

export const featuredVideo = {
  title: "Capsule 1: Les mythes",
  description:
    "Première vidéo de la série Evolution Cloud. On réponds à quelques mythes populaire.",
  youtubeId: "EKnAbWKkB5s",
  duration: "Short"
};
