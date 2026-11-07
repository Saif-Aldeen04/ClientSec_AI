/* Add custom JS code below */ 
setTimeout(() => {
  
const tabsProducts = document.querySelector(".products-with-tabs-component")
console.log(tabsProducts);
const designSelf = `
<section class="design-self py-12 my-8 md:my-32" style="background-color: var(--color-bg-footer);">
  <div data-aos="fade-up" class="container aos-init aos-animate">
    <div class="flex flex-col justify-center items-center gap-8">
      <h4 class="text-white text-2xl text-center leading-loose"> نصمملك على ذوقك وانت اطبعها بطابعتك! </h4>
      <a href="https://wa.me/+966508835859" class="px-8 py-2 text-white rounded-full" style="background-color: var(--color-primary);box-shadow: 0 2px 10px #ffffff5c;">
        <button> صمم الان </button>
      </a>
    </div>
	</div>
</section>
`
tabsProducts.insertAdjacentHTML('afterend', designSelf);

}, 3000);