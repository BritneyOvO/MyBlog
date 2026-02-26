// 友情链接数据配置
// 用于管理友情链接页面的数据

export interface FriendItem {
	id: number;
	title: string;
	imgurl: string;
	desc: string;
	siteurl: string;
	tags: string[];
}

// 友情链接数据
export const friendsData: FriendItem[] = [
  {
    id: 1,
    title: "Liv",
    imgurl: "https://tkazer.github.io/img/butterfly-icon.png",
    desc: "Re | W&M",
    siteurl: "https://tkazer.github.io/",
    tags: ["Framework"],
  },
  {
    id: 2,
    title: "Y&Y",
    imgurl: "https://singlehorn.github.io/images/avatar.jpg",
    desc: "Re | V&N",
    siteurl: "https://singlehorn.github.io/",
    tags: ["Framework"],
  },
  {
    id: 3,
    title: "Hurkin",
    imgurl: "https://www.hurkin.top/wp-content/uploads/2025/02/%E5%8F%8B%E5%88%A9%E5%A5%88%E7%BB%AA1.jpg",
    desc: "Misc | V&N",
    siteurl: "https://www.hurkin.top/",
    tags: ["Framework"],
  },
  {
    id: 4,
    title: "LamentXU",
    imgurl: "https://avatars.githubusercontent.com/u/108666168?v=4",
    desc: "Web | W&M",
    siteurl: "https://www.cnblogs.com/LAMENTXU",
    tags: ["Framework"],
  },
  {
    id: 5,
    title: "PangBai",
    imgurl: "https://pangbai.work/images/avatar.jpg",
    desc: "Re | W&M",
    siteurl: "https://pangbai.work/",
    tags: ["Framework"],
  },
  {
    id: 6,
    title: "astralprisma",
    imgurl: "https://astralprisma.github.io/XH_2.png",
    desc: "Re | N1",
    siteurl: "https://astralprisma.github.io/",
    tags: ["Framework"],
  },
  {
    id: 7,
    title: "Mo1u_",
    imgurl: "https://blog.molulu.top/upload/pZSevJf.jpg",
    desc: "Web | SU",
    siteurl: "https://blog.molulu.top/",
    tags: ["Framework"],
  },
];

// 获取所有友情链接数据
export function getFriendsList(): FriendItem[] {
	return friendsData;
}

// 获取随机排序的友情链接数据
export function getShuffledFriendsList(): FriendItem[] {
	// const shuffled = [...friendsData];
	// for (let i = shuffled.length - 1; i > 0; i--) {
	// 	const j = Math.floor(Math.random() * (i + 1));
	// 	[shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
	// }
	return friendsData;
}
